//! The worker thread of the library.
//!
//! The upstream requests of a verification run on a thread of the library that
//! has a runtime of its own. The caller's thread is never blocked by them and
//! the runtime of the host is never used for them.
//!
//! The thread starts when the first verification is queued, so a host that only
//! asks the bot question pays for nothing. It stops when the last handle of the
//! library is dropped, and a verification that is in flight at that moment is
//! finished before the thread exits.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use time::OffsetDateTime;
use tokio::sync::{mpsc, watch};

use crate::Shared;
use crate::config::EvidencePolicy;
use crate::lock;
use crate::model::{IpVerdict, VerdictInput};
use crate::provider::{LookupProvider, ProviderFinding};

/// A verification that runs or has run for one address.
pub(crate) struct Verification {
    ip: IpAddr,
    result: watch::Sender<Option<IpVerdict>>,
}

impl Verification {
    /// Creates a verification for an address.
    pub(crate) fn new(ip: IpAddr) -> Arc<Self> {
        let (result, _receiver) = watch::channel::<Option<IpVerdict>>(None);
        Arc::new(Self { ip, result })
    }

    /// Publishes the assessment the verification produced.
    fn complete(&self, verdict: IpVerdict) {
        self.result.send_replace(Some(verdict));
    }

    /// Waits for the assessment the verification produces.
    ///
    /// The wait happens on the runtime of the caller, but no request is made
    /// there: the request belongs to the worker thread.
    pub(crate) async fn wait(&self, shared: &Shared) -> IpVerdict {
        let mut receiver = self.result.subscribe();
        loop {
            if let Some(verdict) = receiver.borrow_and_update().clone() {
                return verdict;
            }
            if receiver.changed().await.is_err() {
                return crate::classify(
                    &VerdictInput::new(self.ip),
                    &shared.config,
                    shared.clock.now(),
                );
            }
        }
    }
}

/// A verification the worker has to run.
pub(crate) struct Job {
    pub(crate) ip: IpAddr,
    pub(crate) verification: Arc<Verification>,
}

/// The worker thread of the library.
pub(crate) struct Worker {
    shared: Arc<Shared>,
    state: Mutex<WorkerState>,
}

/// The queue and the thread of the worker.
struct WorkerState {
    sender: mpsc::UnboundedSender<Job>,
    receiver: Option<mpsc::UnboundedReceiver<Job>>,
    thread: Option<JoinHandle<()>>,
    shutdown: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl Worker {
    /// Creates a worker whose thread has not started yet.
    pub(crate) fn new(shared: Arc<Shared>) -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();
        let (shutdown, shutdown_rx) = watch::channel(false);
        Self {
            shared,
            state: Mutex::new(WorkerState {
                sender,
                receiver: Some(receiver),
                thread: None,
                shutdown,
                shutdown_rx,
            }),
        }
    }

    /// Queues a verification and starts the thread when it is not running yet.
    ///
    /// A verification that cannot be queued is completed with the assessment of
    /// the local state, so that the caller that waits for it is not left
    /// waiting.
    pub(crate) fn enqueue(&self, job: Job) {
        let refused = {
            let mut state = lock(&self.state);
            if state.thread.is_none() {
                state.start(Arc::clone(&self.shared));
            }
            state.sender.send(job).err()
        };

        if let Some(refused) = refused {
            let job = refused.0;
            tracing::error!(
                ip = %job.ip,
                "the verification could not be queued for the worker"
            );
            let verdict = self.shared.compose(job.ip, self.shared.clock.now());
            forget_running(&self.shared, job.ip, &job.verification);
            job.verification.complete(verdict);
        }
    }

    /// Stops the thread and waits for the verifications in flight to finish.
    pub(crate) fn stop(&self) {
        let mut state = lock(&self.state);
        let _ = state.shutdown.send(true);
        if let Some(thread) = state.thread.take() {
            let _ = thread.join();
        }
    }
}

impl WorkerState {
    /// Starts the thread of the worker.
    ///
    /// A thread that cannot be started leaves the queue closed, so that the
    /// verifications that are queued are completed with the assessment of the
    /// local state instead of waiting for a worker that never comes.
    fn start(&mut self, shared: Arc<Shared>) {
        let Some(receiver) = self.receiver.take() else {
            return;
        };
        let shutdown = self.shutdown_rx.clone();
        match std::thread::Builder::new()
            .name("badbots-worker".to_string())
            .spawn(move || run(shared, receiver, shutdown))
        {
            Ok(thread) => self.thread = Some(thread),
            Err(error) => {
                tracing::error!(%error, "the worker thread could not be started");
            }
        }
    }
}

/// Runs the queue of the worker until it is told to stop.
fn run(
    shared: Arc<Shared>,
    mut receiver: mpsc::UnboundedReceiver<Job>,
    mut shutdown: watch::Receiver<bool>,
) {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();

    match runtime {
        Ok(runtime) => runtime.block_on(async {
            let mut tasks = tokio::task::JoinSet::new();
            let mut running = true;

            while running {
                tokio::select! {
                    biased;
                    _ = shutdown.changed() => running = false,
                    job = receiver.recv() => {
                        match job {
                            Some(job) => {
                                let shared = Arc::clone(&shared);
                                tasks.spawn(async move {
                                    let _permit = shared.concurrency.acquire().await.ok();
                                    let mut completion = Completion {
                                        shared: Arc::clone(&shared),
                                        ip: job.ip,
                                        verification: Arc::clone(&job.verification),
                                        armed: true,
                                    };
                                    verify(&shared, job.ip, job.verification).await;
                                    completion.disarm();
                                });
                            }
                            None => running = false,
                        }
                    }
                    result = tasks.join_next(), if !tasks.is_empty() => {
                        if let Some(Err(error)) = result {
                            tracing::error!(%error, "a verification of the worker failed");
                        }
                    }
                }
            }

            while tasks.join_next().await.is_some() {}
        }),
        Err(error) => {
            tracing::error!(%error, "the runtime of the worker could not be built");
        }
    }

    abandon(&shared, &mut receiver);
}

/// Completes the verifications that are still queued.
///
/// A verification that is queued when the worker stops never produces an
/// answer, so it is completed with the assessment of the local state and the
/// caller that waits for it is not left waiting.
fn abandon(shared: &Arc<Shared>, receiver: &mut mpsc::UnboundedReceiver<Job>) {
    while let Ok(job) = receiver.try_recv() {
        let verdict = shared.compose(job.ip, shared.clock.now());
        forget_running(shared, job.ip, &job.verification);
        job.verification.complete(verdict);
    }
}

/// Completes a verification whose task did not finish.
///
/// The guard is armed when the task starts and disarmed when the verification
/// publishes its assessment. A task that unwinds leaves the guard armed, so
/// the verification is completed with the assessment of the local state.
struct Completion {
    shared: Arc<Shared>,
    ip: IpAddr,
    verification: Arc<Verification>,
    armed: bool,
}

impl Completion {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for Completion {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        tracing::error!(ip = %self.ip, "the verification of the address did not finish");
        let verdict = self.shared.compose(self.ip, self.shared.clock.now());
        forget_running(&self.shared, self.ip, &self.verification);
        self.verification.complete(verdict);
    }
}

/// Runs one verification and publishes its assessment.
///
/// The verification leaves the map of the running ones before it publishes its
/// assessment, so that a caller that arrives afterwards starts a new
/// verification rather than attaching to one that has already finished.
async fn verify(shared: &Arc<Shared>, ip: IpAddr, verification: Arc<Verification>) {
    let verdict = assess(shared, ip).await;
    forget_running(shared, ip, &verification);
    verification.complete(verdict);
}

/// Removes the verification from the map of the running ones.
fn forget_running(shared: &Shared, ip: IpAddr, verification: &Arc<Verification>) {
    let mut in_flight = lock(&shared.in_flight);
    if in_flight
        .get(&ip)
        .is_some_and(|running| Arc::ptr_eq(running, verification))
    {
        in_flight.remove(&ip);
    }
}

/// Asks the providers about an address and returns the assessment they produce.
///
/// The providers are asked in the order the policy prescribes. The loaded lists
/// are merged first under either policy, because they are local and free. The
/// strict policy then asks the Primary providers one at a time, because a
/// Primary provider may convict on its own, and finally the providers that
/// cannot convict on their own, because asking them one at a time would only
/// add latency. The lenient policy asks every provider from the cheapest to the
/// most expensive one, one at a time, and stops at the first one that hits.
///
/// The assessment of the local state reads the answers in the same order and
/// stops at the same point, so that the coverage of the two is the same.
///
/// An address that cannot be assessed is never asked about: a private or a
/// loopback address has no public reputation and must not reach an upstream.
async fn assess(shared: &Arc<Shared>, ip: IpAddr) -> IpVerdict {
    let now = shared.clock.now();
    let mut input = VerdictInput::new(ip);

    if !crate::model::is_assessable(ip) {
        return crate::classify(&input, &shared.config, now);
    }

    shared.merge_feeds(&mut input);
    if shared.is_bad(&input, now) {
        return crate::classify(&input, &shared.config, now);
    }

    if shared.config.evidence_policy == EvidencePolicy::Lenient {
        for provider in shared.ordered_providers() {
            match ask(shared, provider, ip, now).await {
                Ok(finding) => shared.merge(&mut input, provider.as_ref(), &finding),
                Err(error) => input.coverage.record_failure(provider.id(), error),
            }
            if shared.is_bad(&input, now) {
                return crate::classify(&input, &shared.config, now);
            }
        }

        return crate::classify(&input, &shared.config, now);
    }

    for provider in shared.primary_providers() {
        match ask(shared, provider, ip, now).await {
            Ok(finding) => shared.merge(&mut input, provider.as_ref(), &finding),
            Err(error) => input.coverage.record_failure(provider.id(), error),
        }
        if shared.is_bad(&input, now) {
            return crate::classify(&input, &shared.config, now);
        }
    }

    let corroborating: Vec<_> = shared.corroborating_providers().collect();
    let answers = futures_util::future::join_all(corroborating.iter().map(|provider| {
        let provider = *provider;
        async move {
            let answer = ask(shared, provider, ip, now).await;
            (provider, answer)
        }
    }))
    .await;

    for (provider, answer) in answers {
        match answer {
            Ok(finding) => shared.merge(&mut input, provider.as_ref(), &finding),
            Err(error) => input.coverage.record_failure(provider.id(), error),
        }
    }

    crate::classify(&input, &shared.config, now)
}

/// Asks one provider about an address and remembers the answer.
///
/// The answer and the failure are both remembered, so the next assessment of
/// the address reports them without another request.
async fn ask(
    shared: &Shared,
    provider: &Arc<dyn LookupProvider>,
    ip: IpAddr,
    now: OffsetDateTime,
) -> Result<ProviderFinding, crate::error::ProviderError> {
    let key = crate::cache::CacheKey {
        provider: provider.id(),
        ip,
    };

    let answer = shared
        .cache
        .get_or_fetch(key, now, || async {
            let finding = provider.lookup(ip).await?;
            let expires_at = crate::entry_expiry(&finding, &shared.config, now);
            Ok(crate::cache::CacheEntry {
                value: finding,
                expires_at,
            })
        })
        .await;

    shared.record_attempt(provider.id(), now);
    match &answer {
        Ok(_) => shared.record_success(provider.id(), now),
        Err(error) => shared.record_failure(provider.id(), now, error.clone()),
    }

    answer
}
