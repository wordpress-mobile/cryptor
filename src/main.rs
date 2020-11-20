use log::debug;
use simplelog::*;
use sodiumoxide::base64::Variant;
use sodiumoxide::base64::{decode, encode};
use sodiumoxide::crypto::secretbox;

use std::path::PathBuf;
use structopt::StructOpt;
use structopt_flags::LogLevel;

#[derive(StructOpt)]
#[structopt(
    name = "Cryptor",
    about = "A command-line utility for securely encrypting secrets."
)]
struct Options {
    #[structopt(subcommand)]
    command: Command,

    #[structopt(flatten)]
    verbose: structopt_flags::Verbose,
}

#[derive(StructOpt)]
enum Command {
    /// Generate a new encryption key
    ///
    /// This encryption keys are suitable for encrypting and decrypting files. They're safe to re-use between files.
    GenerateKey,
    /// Encrypt a file, outputting the ciphertext to another file
    EncryptFile {
        /// The full path to the file being encrypted
        ///
        /// Absolute paths are recommended.
        #[structopt(short, long, parse(from_os_str))]
        input_path: PathBuf,

        /// The full path to the output file
        ///
        /// Absolute paths are recommended
        #[structopt(short, long, parse(from_os_str))]
        output_path: PathBuf,

        /// The base-64 secret used to encrypt the file
        ///
        /// A suitable secret can be generated using the `generate-key` subcommand.
        secret: String,
    },
    /// Decrypt a file, outputting the plaintext to another file
    DecryptFile {
        /// The full path to the file being decrypted
        ///
        /// Absolute paths are recommended.
        #[structopt(short, long, parse(from_os_str))]
        input_path: PathBuf,

        /// The full path to the output file
        ///
        /// Absolute paths are recommended
        #[structopt(short, long, parse(from_os_str))]
        output_path: PathBuf,

        /// The base-64 secret used to encrypt the file. This will be automatically read from the `ENCRYPTION_SECRET` environment variable, if present.
        ///
        /// A suitable secret can be generated using the `generate-key` subcommand.
        #[structopt(short, long, env = "ENCRYPTION_SECRET")]
        secret: String,
    },
}

fn main() {
    let log_level_filter = Options::from_args().verbose.get_level_filter();

    CombinedLogger::init(vec![TermLogger::new(
        log_level_filter,
        Config::default(),
        TerminalMode::Mixed,
    )
    .unwrap()])
    .unwrap();

    debug!("Initializing libsodium");
    sodiumoxide::init().expect("Unable to initialize libsodium");
    debug!("Finished initializing libsodium");

    debug!("Parsing command line arguments");

    match Options::from_args().command {
        Command::GenerateKey => generate_key(),
        Command::EncryptFile {
            input_path,
            output_path,
            secret,
        } => encrypt_file(input_path, output_path, secret),
        Command::DecryptFile {
            input_path,
            output_path,
            secret,
        } => decrypt_file(input_path, output_path, secret),
    }
}

fn generate_key() {
    debug!("Generating an encryption key");
    let key_bytes = secretbox::gen_key();
    println!("Your Unique Encryption Key: {:?}", encode_key(key_bytes));
}

fn encrypt_file(input_path: PathBuf, output_path: PathBuf, secret: String) {
    let content = std::fs::read(input_path).expect("could not read file");
    let ciphertext = encrypt_bytes(content, decode_key(secret));
    std::fs::write(&output_path, &ciphertext).expect("Unable to write to file");
}

fn decrypt_file(input_path: PathBuf, output_path: PathBuf, secret: String) {
    let content = std::fs::read(input_path).expect("Could not read input file");
    let decrypted_bytes = decrypt_bytes(content, decode_key(secret));
    std::fs::write(&output_path, decrypted_bytes).expect("Could not write to output file");
}

fn encrypt_bytes(input: Vec<u8>, key: sodiumoxide::crypto::secretbox::Key) -> Vec<u8> {
    let nonce = secretbox::gen_nonce();
    let secret_bytes = secretbox::seal(&input, &nonce, &key);
    [&nonce[..], b":", &secret_bytes].concat()
}

fn decrypt_bytes(input: Vec<u8>, key: sodiumoxide::crypto::secretbox::Key) -> Vec<u8> {
    // Encoded Format byte layout:
    // |======================================|=====================================|
    // | 0                                 24 | 25                                ∞ |
    // |======================================|=====================================|
    // |                nonce                 |           encrypted data            |
    // |======================================|=====================================|

    const NONCE_SIZE: usize = 24;
    const DATA_OFFSET: usize = NONCE_SIZE + 1;

    let data_bytes = &input[DATA_OFFSET..];

    let mut nonce_bytes: [u8; NONCE_SIZE] = Default::default();
    nonce_bytes.copy_from_slice(&input[0..NONCE_SIZE]);
    let nonce = sodiumoxide::crypto::secretbox::Nonce(nonce_bytes);

    secretbox::open(&data_bytes, &nonce, &key).expect("Unable to decrypt message")
}

fn encode_key(key: sodiumoxide::crypto::secretbox::Key) -> String {
    encode(&key, Variant::Original)
}

fn decode_key(key: String) -> sodiumoxide::crypto::secretbox::Key {
    let decoded_key_bytes = decode(key, Variant::Original).expect("Unable to decode key");

    let mut key_bytes: [u8; 32] = Default::default();
    key_bytes.copy_from_slice(&decoded_key_bytes);

    sodiumoxide::crypto::secretbox::Key(key_bytes)
}
