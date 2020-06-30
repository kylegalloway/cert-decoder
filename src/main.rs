use std::path::Path;

/// This trait helps abstract away IO operations.
/// It allows a fake implementation to be used in testing.
trait PathValidator {
    fn is_file(&self, path: &str) -> bool;
}

/// The "real" version of the PathValidator
struct CertValidator;

impl PathValidator for CertValidator {
    fn is_file(&self, path: &str) -> bool {
        Path::new(path).is_file()
    }
}

fn execute(validator: impl PathValidator, args: Vec<String>) -> Result<(), String> {
    // Check args length
    if args.len() != 1 {
        let err_msg = String::from("Error: did not receive a single argument, please invoke cert-decoder as follows: ./cert-decoder /path/to/cert.");
        return Err(err_msg);
    }

    let path = &args[0];

    // Check if arg is a file
    if !validator.is_file(path) {
        let err_msg = String::from("Error: path given as argument is not a regular file, it must be a path to a certificate!");
        return Err(err_msg);
    }

    Ok(())
}

fn main() -> Result<(), String> {
    let args = std::env::args().skip(1).collect();
    let validator = CertValidator;
    execute(validator, args)
}

#[cfg(test)]
mod test {

    use crate::{execute, PathValidator};

    struct FakeValidator {
        is_file: bool,
    }

    impl PathValidator for FakeValidator {
        fn is_file(&self, _: &str) -> bool {
            self.is_file
        }
    }

    #[test]
    fn should_error_if_not_given_a_single_argument() {
        // arrange
        let args = Vec::new();
        let validator = FakeValidator { is_file: true };

        // act
        let result = execute(validator, args);

        // assert
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            String::from(
                "Error: did not receive a single argument, please invoke cert-decoder as follows: ./cert-decoder /path/to/cert."
            )
        )
    }

    #[test]
    fn should_error_if_argument_is_not_a_regular_file() {
        // arrange
        let args = vec![String::from("does-not-exist")];
        let validator = FakeValidator { is_file: false };

        // act
        let result = execute(validator, args);

        // assert
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            "Error: path given as argument is not a regular file, it must be a path to a certificate!"
        )
    }

    #[test]
    fn should_succeed() {
        // arrange
        let args = vec![String::from("a-file")];
        let validator = FakeValidator { is_file: true };

        // act
        let result = execute(validator, args);

        // assert
        assert!(result.is_ok());
    }
}
