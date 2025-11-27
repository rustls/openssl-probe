use std::env;
use std::path::{Path, PathBuf};

/// Probe for SSL certificates on the system, then configure the SSL certificate `SSL_CERT_FILE`
/// and `SSL_CERT_DIR` environment variables in this process for OpenSSL to use.
///
/// Preconfigured values in the environment variables will not be overwritten if the paths they
/// point to exist and are accessible.
///
/// Returns `true` if any certificate file or directory was found while probing.
/// Combine this with `has_ssl_cert_env_vars()` to check whether previously configured environment
/// variables are valid.
///
/// # Safety
///
/// This function is not safe because it mutates the process's environment
/// variables which is generally not safe. See the [documentation in libstd][doc]
/// for information about why setting environment variables is not safe.
///
/// If possible use the [`probe`] function and directly configure OpenSSL
/// methods instead of relying on environment variables.
///
/// [doc]: https://doc.rust-lang.org/stable/std/env/fn.set_var.html#safety
pub unsafe fn try_init_openssl_env_vars() -> bool {
    let ProbeResult {
        cert_file,
        cert_dir,
    } = probe();
    // we won't be overwriting existing env variables because if they're valid probe() will have
    // returned them unchanged
    if let Some(path) = &cert_file {
        unsafe {
            put(ENV_CERT_FILE, path);
        }
    }
    if let Some(path) = &cert_dir {
        unsafe {
            put(ENV_CERT_DIR, path);
        }
    }

    unsafe fn put(var: &str, path: &Path) {
        // Avoid calling `setenv` if the variable already has the same contents. This avoids a
        // crash when called from out of perl <5.38 (Debian Bookworm is at 5.36), as old versions
        // of perl tend to manipulate the `environ` pointer directly.
        if env::var_os(var).as_deref() != Some(path.as_os_str()) {
            unsafe {
                env::set_var(var, path);
            }
        }
    }

    cert_file.is_some() || cert_dir.is_some()
}

/// Probe the current system for the "cert file" and "cert dir" variables that
/// OpenSSL typically requires.
///
/// The probe result is returned as a [`ProbeResult`] structure here.
pub fn probe() -> ProbeResult {
    let mut result = ProbeResult::from_env();
    if result.cert_file.is_none() {
        result.cert_file =
            CERTIFICATE_FILE_NAMES
                .iter()
                .find_map(|p| match Path::new(p).exists() {
                    true => Some(PathBuf::from(p)),
                    false => None,
                });
    }

    for certs_dir in candidate_cert_dirs() {
        if result.cert_dir.is_none() {
            let cert_dir = certs_dir.join("certs");
            if cert_dir.exists() {
                result.cert_dir = Some(cert_dir);
            }
        }
        if result.cert_file.is_some() && result.cert_dir.is_some() {
            break;
        }
    }
    result
}

/// Probe the system for the directory in which CA certificates should likely be
/// found.
///
/// This will only search known system locations.
pub fn candidate_cert_dirs() -> impl Iterator<Item = &'static Path> {
    CERTIFICATE_DIRS
        .iter()
        .map(Path::new)
        .filter(|p| p.exists())
}

/// Check whether the OpenSSL `SSL_CERT_FILE` and/or `SSL_CERT_DIR` environment variable is
/// configured in this process with an existing file or directory.
///
/// That being the case would indicate that certificates will be found successfully by OpenSSL.
///
/// Returns `true` if either variable is set to an existing file or directory.
pub fn has_ssl_cert_env_vars() -> bool {
    let probe = ProbeResult::from_env();
    probe.cert_file.is_some() || probe.cert_dir.is_some()
}

pub struct ProbeResult {
    pub cert_file: Option<PathBuf>,
    pub cert_dir: Option<PathBuf>,
}

impl ProbeResult {
    fn from_env() -> ProbeResult {
        let var = |name| env::var_os(name).map(PathBuf::from).filter(|p| p.exists());
        ProbeResult {
            cert_file: var(ENV_CERT_FILE),
            cert_dir: var(ENV_CERT_DIR),
        }
    }
}

// see http://gagravarr.org/writing/openssl-certs/others.shtml
const CERTIFICATE_DIRS: &[&str] = &[
    "/var/ssl",
    "/usr/share/ssl",
    "/usr/local/ssl",
    "/usr/local/openssl",
    "/usr/local/etc/openssl", // MacPorts, https://github.com/rustls/openssl-probe/pull/15
    "/usr/local/share",
    "/usr/lib/ssl",
    "/usr/ssl",
    "/etc/openssl",
    "/etc/pki/ca-trust/extracted/pem",
    "/etc/pki/tls",
    "/etc/ssl",
    "/etc/certs",
    "/opt/etc/ssl", // Entware
    #[cfg(target_os = "android")]
    "/data/data/com.termux/files/usr/etc/tls",
    #[cfg(target_os = "haiku")]
    "/boot/system/data/ssl",
];

// cert.pem looks to be an openssl 1.0.1 thing, while
// certs/ca-certificates.crt appears to be a 0.9.8 thing
const CERTIFICATE_FILE_NAMES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Gentoo, Joyent SmartOS, etc.
    #[cfg(target_os = "linux")]
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // CentOS, RHEL 7 (should come before RHEL 6)
    #[cfg(target_os = "linux")]
    "/etc/pki/tls/certs/ca-bundle.crt", // Fedora, RHEL 6
    #[cfg(target_os = "linux")]
    "/etc/ssl/ca-bundle.pem", // OpenSUSE
    #[cfg(target_os = "linux")]
    "/etc/pki/tls/cacert.pem", // OpenELEC (a media center Linux distro)
    #[cfg(any(target_os = "linux", target_os = "openbsd"))]
    "/etc/ssl/cert.pem", // Alpine Linux, OpenBSD
    #[cfg(target_os = "freebsd")]
    "/usr/local/etc/ssl/cert.pem", // FreeBSD
    #[cfg(target_os = "dragonfly")]
    "/usr/local/share/certs/ca-root-nss.crt", // DragonFly
    #[cfg(target_os = "netbsd")]
    "/etc/openssl/certs/ca-certificates.crt", // NetBSD
    #[cfg(target_os = "solaris")]
    "/etc/certs/ca-certificates.crt", // Solaris 11.2+
    #[cfg(target_os = "illumos")]
    "/etc/ssl/cacert.pem", // OmniOS, https://github.com/rustls/openssl-probe/pull/22
    #[cfg(target_os = "illumos")]
    "/etc/certs/ca-certificates.crt", // OpenIndiana, https://github.com/rustls/openssl-probe/pull/22
    #[cfg(target_os = "android")]
    "/data/data/com.termux/files/usr/etc/tls/cert.pem", // Termux on Android, https://github.com/rustls/openssl-probe/pull/2
    #[cfg(target_os = "haiku")]
    "/boot/system/data/ssl/CARootCertificates.pem", // Haiku, https://github.com/rustls/openssl-probe/pull/4
    #[cfg(target_os = "linux")]
    "/opt/etc/ssl/certs/ca-certificates.crt", // Entware, https://github.com/rustls/openssl-probe/pull/21
];

/// The OpenSSL environment variable to configure what certificate file to use.
pub const ENV_CERT_FILE: &'static str = "SSL_CERT_FILE";

/// The OpenSSL environment variable to configure what certificates directory to use.
pub const ENV_CERT_DIR: &'static str = "SSL_CERT_DIR";
