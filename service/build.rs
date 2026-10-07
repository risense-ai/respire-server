//! Compile immutable API provenance. No frontend assets are generated or embedded.

fn revision(value: Option<String>) -> Result<String, &'static str> {
    let value = value.unwrap_or_else(|| "unknown".to_owned());
    if value == "unknown"
        || (value.len() == 40
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    {
        Ok(value)
    } else {
        Err("RSRS_BUILD_REVISION must be a full lowercase Git SHA or unknown")
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=RSRS_BUILD_REVISION");
    let setting = match std::env::var("RSRS_BUILD_REVISION") {
        Ok(value) => Some(value),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            eprintln!("RSRS_BUILD_REVISION must be valid UTF-8");
            std::process::exit(1);
        }
    };
    match revision(setting) {
        Ok(value) => println!("cargo:rustc-env=RSRS_COMPILED_REVISION={value}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::revision;
    #[test]
    fn unversioned_builds_are_explicitly_unknown() {
        assert_eq!(revision(None), Ok("unknown".to_owned()));
        assert_eq!(
            revision(Some("unknown".to_owned())),
            Ok("unknown".to_owned())
        );
    }
    #[test]
    fn only_complete_lowercase_revision_is_accepted() {
        let sha = "84ad000ae50758756edb077c63c0a1b31eb9ada2";
        assert_eq!(revision(Some(sha.to_owned())), Ok(sha.to_owned()));
        for invalid in [
            "",
            "main",
            "84ad000",
            "84AD000AE50758756EDB077C63C0A1B31EB9ADA2",
            "fffffffffffffffffffffffffffffffffffffff\n",
            "gggggggggggggggggggggggggggggggggggggggg",
        ] {
            assert!(revision(Some(invalid.to_owned())).is_err());
        }
    }
}
