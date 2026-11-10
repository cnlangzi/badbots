//! The request-level user-agent dimension.
//!
//! The user-agent dimension is independent of the badness dimension: it never
//! changes an IP verdict and an IP verdict never changes it. A user agent that
//! claims to be a well-known bot is never treated as verified.

use serde::{Deserialize, Serialize};

use crate::model::classification::IpVerdict;

/// The syntactic state of a user-agent header.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UaState {
    /// The header is present and well formed.
    Present,
    /// The header is present but violates RFC 9110.
    Malformed,
    /// The header was not sent.
    Missing,
}

/// The kind of non-browser client a user agent declares.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BotKind {
    /// A crawler that indexes content.
    Crawler,
    /// An automation or command line client.
    Automation,
}

/// The user-agent dimension of a request.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct BotVerdict {
    /// Whether the user agent is a bot or a non-browser client.
    pub is_bot: bool,
    /// The syntactic state of the header.
    pub ua_state: UaState,
    /// The kind of client, when one was recognised.
    pub kind: Option<BotKind>,
    /// The family the user agent claims, when one was recognised.
    pub claimed_family: Option<String>,
    /// The markers that matched.
    pub matched_markers: Vec<String>,
}

/// The verdict for one request.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct RequestVerdict {
    /// The verdict for the source address.
    pub ip: IpVerdict,
    /// The verdict for the user agent.
    pub bot: BotVerdict,
}

/// The marker lists used to classify a user agent.
#[derive(Clone, Debug, Default)]
pub struct UserAgentMarkers {
    /// Markers of a user agent that declares itself a crawler.
    pub crawler_markers: Vec<String>,
    /// Markers of a user agent that declares itself an automation tool.
    pub automation_markers: Vec<String>,
    /// Markers of a browser.
    pub browser_features: Vec<String>,
    /// Recognised crawler families and the marker that identifies them.
    pub families: Vec<(String, String)>,
}

impl UserAgentMarkers {
    /// The compiled-in marker lists.
    pub fn defaults() -> Self {
        Self {
            crawler_markers: DEFAULT_CRAWLER_MARKERS
                .iter()
                .map(|m| (*m).to_string())
                .collect(),
            automation_markers: DEFAULT_AUTOMATION_MARKERS
                .iter()
                .map(|m| (*m).to_string())
                .collect(),
            browser_features: DEFAULT_BROWSER_FEATURES
                .iter()
                .map(|m| (*m).to_string())
                .collect(),
            families: DEFAULT_FAMILIES
                .iter()
                .map(|(marker, family)| ((*marker).to_string(), (*family).to_string()))
                .collect(),
        }
    }
}

/// Markers of a user agent that declares itself a crawler.
pub const DEFAULT_CRAWLER_MARKERS: &[&str] = &[
    "bot",
    "crawler",
    "spider",
    "crawling",
    "scraper",
    "scrapy",
    "slurp",
    "archiver",
    "indexer",
    "yandex",
    "baiduspider",
    "bingpreview",
    "applebot",
    "petalbot",
    "duckduckbot",
    "ccbot",
    "gptbot",
    "oai-searchbot",
    "chatgpt-user",
    "claudebot",
    "claude-web",
    "anthropic-ai",
    "perplexitybot",
    "perplexity-user",
    "amazonbot",
    "bytespider",
    "cohere-ai",
    "diffbot",
    "meta-externalagent",
    "ahrefsbot",
    "semrushbot",
    "mj12bot",
    "dotbot",
    "rogerbot",
    "uptimerobot",
    "pingdom",
    "zgrab",
    "masscan",
    "nmap",
];

/// Markers of a user agent that declares itself an automation tool.
pub const DEFAULT_AUTOMATION_MARKERS: &[&str] = &[
    "curl",
    "wget",
    "python-requests",
    "python-urllib",
    "aiohttp",
    "httpx",
    "go-http-client",
    "java/",
    "apache-httpclient",
    "okhttp",
    "postmanruntime",
    "insomnia",
    "libwww-perl",
    "guzzlehttp",
    "node-fetch",
    "axios",
    "powershell",
    "restsharp",
    "httpie",
    "headlesschrome",
    "phantomjs",
    "puppeteer",
    "playwright",
    "selenium",
    "lighthouse",
    "nikto",
    "sqlmap",
    "gobuster",
    "wpscan",
    "nessus",
    "openvas",
    "whatweb",
];

/// Markers of a browser.
pub const DEFAULT_BROWSER_FEATURES: &[&str] = &[
    "mozilla/",
    "applewebkit",
    "gecko/",
    "chrome/",
    "safari/",
    "firefox/",
    "edg/",
    "opr/",
    "trident/",
    "msie",
];

/// Recognised crawler families and the marker that identifies them.
pub const DEFAULT_FAMILIES: &[(&str, &str)] = &[
    ("googlebot", "Googlebot"),
    ("google-inspectiontool", "Google InspectionTool"),
    ("bingbot", "Bingbot"),
    ("bingpreview", "BingPreview"),
    ("yandexbot", "YandexBot"),
    ("baiduspider", "Baiduspider"),
    ("duckduckbot", "DuckDuckBot"),
    ("applebot", "Applebot"),
    ("petalbot", "PetalBot"),
    ("ccbot", "CCBot"),
    ("gptbot", "GPTBot"),
    ("oai-searchbot", "OAI-SearchBot"),
    ("chatgpt-user", "ChatGPT-User"),
    ("claudebot", "ClaudeBot"),
    ("claude-web", "Claude-Web"),
    ("anthropic-ai", "Anthropic-ai"),
    ("perplexitybot", "PerplexityBot"),
    ("perplexity-user", "Perplexity-User"),
    ("amazonbot", "Amazonbot"),
    ("bytespider", "Bytespider"),
    ("cohere-ai", "Cohere-ai"),
    ("diffbot", "Diffbot"),
    ("meta-externalagent", "Meta-ExternalAgent"),
    ("facebookbot", "FacebookBot"),
    ("twitterbot", "Twitterbot"),
    ("linkedinbot", "LinkedInBot"),
    ("slackbot", "Slackbot"),
    ("discordbot", "Discordbot"),
    ("telegrambot", "TelegramBot"),
    ("ahrefsbot", "AhrefsBot"),
    ("semrushbot", "SemrushBot"),
    ("mj12bot", "MJ12bot"),
    ("dotbot", "DotBot"),
    ("rogerbot", "RogerBot"),
    ("uptimerobot", "UptimeRobot"),
    ("pingdom", "Pingdom"),
];

/// Whether a character may appear in a product token.
fn is_tchar(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '!' | '#'
                | '$'
                | '%'
                | '&'
                | '\''
                | '*'
                | '+'
                | '-'
                | '.'
                | '^'
                | '_'
                | '`'
                | '|'
                | '~'
        )
}

/// Whether a character may appear in a field value.
fn is_field_char(c: char) -> bool {
    matches!(c, '\t' | ' ')
        || ('\u{21}'..='\u{7e}').contains(&c)
        || ('\u{80}'..='\u{ff}').contains(&c)
}

fn skip_quoted_string(chars: &[char], start: usize) -> Option<usize> {
    let mut index = start + 1;
    while index < chars.len() {
        match chars[index] {
            '\\' => index += 2,
            '"' => return Some(index + 1),
            _ => index += 1,
        }
    }
    None
}

fn skip_comment(chars: &[char], start: usize) -> Option<usize> {
    let mut index = start + 1;
    while index < chars.len() {
        match chars[index] {
            '\\' => index += 2,
            '"' => index = skip_quoted_string(chars, index)?,
            ')' => return Some(index + 1),
            _ => index += 1,
        }
    }
    None
}

/// Whether a user agent is a well formed field value that parses as a product list
/// with optional comments, as described by RFC 9110 section 10.1.5.
pub fn is_well_formed_user_agent(user_agent: &str) -> bool {
    if user_agent.is_empty() {
        return false;
    }
    if !user_agent.chars().all(is_field_char) {
        return false;
    }

    let chars: Vec<char> = user_agent.chars().collect();
    let mut index = 0;
    let mut products = 0;

    while index < chars.len() {
        match chars[index] {
            ' ' | '\t' => index += 1,
            '(' => match skip_comment(&chars, index) {
                Some(next) => index = next,
                None => return false,
            },
            c if is_tchar(c) => {
                while index < chars.len() && is_tchar(chars[index]) {
                    index += 1;
                }
                products += 1;
                if index < chars.len() && chars[index] == '/' {
                    index += 1;
                    if index < chars.len() && chars[index] == '"' {
                        match skip_quoted_string(&chars, index) {
                            Some(next) => index = next,
                            None => return false,
                        }
                    } else {
                        let version_start = index;
                        while index < chars.len() && is_tchar(chars[index]) {
                            index += 1;
                        }
                        if index == version_start {
                            return false;
                        }
                    }
                }
                if index < chars.len() && !matches!(chars[index], ' ' | '\t' | '(') {
                    return false;
                }
            }
            _ => return false,
        }
    }

    products > 0
}

/// The syntactic state of a user-agent header.
pub fn ua_state(user_agent: Option<&str>) -> UaState {
    match user_agent {
        None => UaState::Missing,
        Some(value) if is_well_formed_user_agent(value) => UaState::Present,
        Some(_) => UaState::Malformed,
    }
}

/// Classifies a user agent against the marker lists.
///
/// A user agent is a bot when it declares itself one or when it carries none of
/// the browser features.
pub fn classify_user_agent(user_agent: Option<&str>, markers: &UserAgentMarkers) -> BotVerdict {
    let state = ua_state(user_agent);
    let Some(value) = user_agent else {
        return BotVerdict {
            is_bot: false,
            ua_state: state,
            kind: None,
            claimed_family: None,
            matched_markers: Vec::new(),
        };
    };

    let lowered = value.to_ascii_lowercase();
    let mut matched: Vec<String> = Vec::new();
    let mut kind: Option<BotKind> = None;

    for (marker, family) in &markers.families {
        if lowered.contains(&marker.to_ascii_lowercase()) {
            matched.push((*marker).clone());
            kind = Some(BotKind::Crawler);
            return BotVerdict {
                is_bot: true,
                ua_state: state,
                kind,
                claimed_family: Some(family.clone()),
                matched_markers: matched,
            };
        }
    }

    for marker in &markers.crawler_markers {
        if lowered.contains(&marker.to_ascii_lowercase()) {
            matched.push(marker.clone());
            kind = Some(BotKind::Crawler);
        }
    }
    for marker in &markers.automation_markers {
        if lowered.contains(&marker.to_ascii_lowercase()) {
            matched.push(marker.clone());
            kind.get_or_insert(BotKind::Automation);
        }
    }

    let mut browser_features = 0;
    for marker in &markers.browser_features {
        if lowered.contains(&marker.to_ascii_lowercase()) {
            matched.push(marker.clone());
            browser_features += 1;
        }
    }

    let is_bot = kind.is_some() || browser_features == 0;

    BotVerdict {
        is_bot,
        ua_state: state,
        kind: if is_bot {
            kind.or(Some(BotKind::Automation))
        } else {
            None
        },
        claimed_family: None,
        matched_markers: matched,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        BotKind, UaState, UserAgentMarkers, classify_user_agent, is_well_formed_user_agent,
        ua_state,
    };

    fn markers() -> UserAgentMarkers {
        UserAgentMarkers::defaults()
    }

    #[test]
    fn accepts_well_formed_user_agents() {
        assert!(is_well_formed_user_agent(
            "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/121.0"
        ));
        assert!(is_well_formed_user_agent("curl/8.4.0"));
        assert!(is_well_formed_user_agent(
            "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        ));
        assert!(is_well_formed_user_agent("MyApp/1.0 (build 42)"));
    }

    #[test]
    fn rejects_malformed_user_agents() {
        assert!(!is_well_formed_user_agent("Mozilla/5.0 (unclosed"));
        assert!(!is_well_formed_user_agent("bad\0value"));
        assert!(!is_well_formed_user_agent(""));
        assert!(!is_well_formed_user_agent("(only a comment)"));
    }

    #[test]
    fn reports_the_syntactic_state() {
        assert_eq!(ua_state(None), UaState::Missing);
        assert_eq!(ua_state(Some("curl/8.4.0")), UaState::Present);
        assert_eq!(ua_state(Some("Mozilla/5.0 (unclosed")), UaState::Malformed);
        assert_eq!(ua_state(Some("")), UaState::Malformed);
    }

    #[test]
    fn classifies_a_browser_user_agent() {
        let verdict = classify_user_agent(
            Some("Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/121.0"),
            &markers(),
        );
        assert!(!verdict.is_bot);
        assert_eq!(verdict.ua_state, UaState::Present);
        assert_eq!(verdict.kind, None);
    }

    #[test]
    fn classifies_a_declared_crawler() {
        let verdict = classify_user_agent(
            Some("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
            &markers(),
        );
        assert!(verdict.is_bot);
        assert_eq!(verdict.kind, Some(BotKind::Crawler));
        assert_eq!(verdict.claimed_family.as_deref(), Some("Googlebot"));
    }

    #[test]
    fn classifies_a_declared_tool() {
        let verdict = classify_user_agent(Some("curl/8.0"), &markers());
        assert!(verdict.is_bot);
        assert_eq!(verdict.kind, Some(BotKind::Automation));
    }

    #[test]
    fn classifies_a_bare_product_token() {
        let verdict = classify_user_agent(Some("MyApp/1.0"), &markers());
        assert!(verdict.is_bot);
        assert_eq!(verdict.ua_state, UaState::Present);
    }

    #[test]
    fn classifies_a_missing_user_agent() {
        let verdict = classify_user_agent(None, &markers());
        assert!(!verdict.is_bot);
        assert_eq!(verdict.ua_state, UaState::Missing);
    }

    #[test]
    fn classifies_a_malformed_user_agent() {
        let verdict = classify_user_agent(Some("Mozilla/5.0 (unclosed"), &markers());
        assert_eq!(verdict.ua_state, UaState::Malformed);
        assert!(!verdict.is_bot);

        let verdict = classify_user_agent(Some("bad\0value"), &markers());
        assert_eq!(verdict.ua_state, UaState::Malformed);
        assert!(verdict.is_bot);
    }
}
