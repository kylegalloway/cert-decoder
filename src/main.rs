use std::path::Path;
use x509_parser::parse_x509_der;
use x509_parser::pem::pem_to_der;

/// This trait helps abstract away IO operations.
/// It allows a fake implementation to be used in testing.
trait FileProcessor {
    fn is_file(&self, path: &str) -> bool;
    fn read_to_string(&self, path: &str) -> Result<String, Box<dyn std::error::Error>>;
}

/// The "real" version of the FileProcessor
struct CertProcessor;

impl FileProcessor for CertProcessor {
    fn is_file(&self, path: &str) -> bool {
        Path::new(path).is_file()
    }
    fn read_to_string(&self, path: &str) -> Result<String, Box<dyn std::error::Error>> {
        let path_str = std::fs::read_to_string(path)?;
        Ok(path_str)
    }
}

fn execute(
    processor: impl FileProcessor,
    args: Vec<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Check args length
    if args.len() != 1 {
        let err_msg = String::from("Error: did not receive a single argument, please invoke cert-decoder as follows: ./cert-decoder /path/to/cert.");
        return Err(err_msg.into());
    }

    let path = &args[0];

    // Check if arg is a file
    if !processor.is_file(path) {
        let err_msg = String::from("Error: path given as argument is not a regular file, it must be a path to a certificate!");
        return Err(err_msg.into());
    }

    // Convert pem file to der file then parse it
    let cert = processor.read_to_string(path)?;
    let (_, pem) = pem_to_der(cert.as_bytes())?;
    let (_, parsed_cert) = parse_x509_der(&pem.contents)?;
    let output = format!("{:#?}", parsed_cert.tbs_certificate);

    println!("{}", output);

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect();
    let processor = CertProcessor;
    execute(processor, args)
}

#[cfg(test)]
mod test {

    use crate::{execute, FileProcessor};

    // deriving default gives a basic implementation of the struct with default fields
    // i.e. false for bool and "" for String
    #[derive(Default)]
    struct FakeProcessor {
        is_file: bool,
        file_str: String,
    }

    impl FileProcessor for FakeProcessor {
        fn is_file(&self, _: &str) -> bool {
            self.is_file
        }
        fn read_to_string(&self, _: &str) -> Result<String, Box<dyn std::error::Error>> {
            Ok(self.file_str.clone())
        }
    }

    #[test]
    fn should_error_if_not_given_a_single_argument() {
        let args = Vec::new();
        let processor = FakeProcessor::default();

        let result = execute(processor, args);

        assert!(result.is_err());
        assert_eq!(
            format!("{}", result.err().unwrap()),
            String::from(
                "Error: did not receive a single argument, please invoke cert-decoder as follows: ./cert-decoder /path/to/cert."
            )
        )
    }

    #[test]
    fn should_error_if_argument_is_not_a_regular_file() {
        let args = vec![String::from("does-not-exist")];
        let processor = FakeProcessor::default();

        let result = execute(processor, args);

        assert!(result.is_err());
        assert_eq!(
            format!("{}", result.err().unwrap()),
            "Error: path given as argument is not a regular file, it must be a path to a certificate!"
        )
    }

    #[test]
    fn should_error_if_given_argument_is_not_a_pem_encoded_certificate() {
        let args = vec![String::from("Cargo.toml")];
        let processor = FakeProcessor {
            is_file: true,
            ..FakeProcessor::default() // This syntax fills in missing fields from given struct (in this case default)
        };

        let result = execute(processor, args);

        assert!(result.is_err());
    }

    #[test]
    fn should_error_if_argument_is_not_a_valid_certificate() {
        let cert = include_str!("../resources/bad.crt"); // include_str makes a string from the file contents
        let args = vec![String::from("does-not-matter")];
        let processor = FakeProcessor {
            is_file: true,
            file_str: String::from(cert),
        };

        let result = execute(processor, args);

        assert!(result.is_err());
    }

    #[test]
    fn should_succeed() {
        let cert = include_str!("../resources/google.com.crt"); // include_str makes a string from the file contents
        let args = vec![String::from("does-not-matter")];
        let processor = FakeProcessor {
            is_file: true,
            file_str: String::from(cert),
        };

        let result = execute(processor, args);

        assert!(result.is_ok());
    }
}
