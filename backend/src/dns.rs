//! Domain -> IP lookup, so a website can be blocked without knowing its addresses.
//! Uses the operating system's resolver (same answer the PC itself would get), no extra crates.

use std::net::{IpAddr, ToSocketAddrs};

/// Accepts "example.com", "www.example.com", or a pasted URL like "https://example.com/page?x=1"
/// and returns just the host name, or an error explaining what is wrong.
pub fn clean_domain(raw: &str) -> Result<String, String> {
    let mut s = raw.trim().to_lowercase();
    if let Some((_, rest)) = s.split_once("://") {
        s = rest.to_string();
    }
    s = s.split(|c| c == '/' || c == '?' || c == '#').next().unwrap_or("").to_string();
    if let Some((_, host)) = s.rsplit_once('@') {
        s = host.to_string(); // drop user:pass@
    }
    if let Some((host, port)) = s.rsplit_once(':') {
        if port.chars().all(|c| c.is_ascii_digit()) {
            s = host.to_string(); // drop :port
        }
    }
    let s = s.trim_end_matches('.').to_string();

    if s.parse::<IpAddr>().is_ok() {
        return Err("that is already an IP address, put it in Remote address".into());
    }
    let ok = !s.is_empty()
        && s.len() <= 253
        && s.contains('.')
        && s.split('.').all(|l| {
            !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-') && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
    if ok {
        Ok(s)
    } else {
        Err("enter a domain such as example.com (letters, numbers, dots and hyphens)".into())
    }
}

/// All addresses (IPv4 first) the system resolver returns for the domain.
pub fn resolve(domain: &str) -> Result<Vec<IpAddr>, String> {
    let mut ips: Vec<IpAddr> = (domain, 0u16)
        .to_socket_addrs()
        .map_err(|_| format!("could not find {domain}, check the spelling and your internet connection"))?
        .map(|a| a.ip())
        .collect();
    ips.sort_by_key(|ip| (ip.is_ipv6(), *ip));
    ips.dedup();
    if ips.is_empty() {
        return Err(format!("{domain} has no IP addresses"));
    }
    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::clean_domain;

    #[test]
    fn cleans_urls_and_hosts() {
        assert_eq!(clean_domain("https://User:pw@WWW.Example.com:8080/a/b?x=1#y").unwrap(), "www.example.com");
        assert_eq!(clean_domain("example.com.").unwrap(), "example.com");
        assert_eq!(clean_domain("  sub-1.example.co.uk ").unwrap(), "sub-1.example.co.uk");
    }

    #[test]
    fn rejects_bad_input() {
        for bad in ["", "localhost", "1.2.3.4", "-a.com", "a..com", "exa mple.com", "a.com; rm -rf", "http://"] {
            assert!(clean_domain(bad).is_err(), "{bad} should be rejected");
        }
    }
}
