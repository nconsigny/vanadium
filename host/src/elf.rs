use goblin::elf::program_header::{PT_LOAD, PF_R, PF_W, PF_X};
use goblin::elf::{Elf, ProgramHeader};

use std::io;
use std::io::Read;
use std::path::Path;
use std::fs::File;

#[derive(Debug)]
pub struct Segment {
    pub data: Vec<u8>,
    pub start: u32,
    pub end: u32,
}

impl Segment {
    fn new(segment: &ProgramHeader, data: &[u8]) -> Self {
        let size = segment.p_filesz as u32;
        let start = segment.p_vaddr as u32;

        Self {
            data: data.to_vec(),
            start: start,
            end: start + size,
        }
    }
}


#[derive(Debug)]
pub struct ElfFile {
    pub code_segment: Segment,
    pub data_segment: Segment,
    pub entrypoint: u32,
}

impl ElfFile {
    pub fn new(path: &Path) -> io::Result<Self> {
        let mut file = File::open(path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let elf = Elf::parse(&buffer).unwrap();
        assert_eq!(elf.header.e_machine, goblin::elf::header::EM_RISCV);

        let (code_segment, data_segment) = Self::parse_segments(&elf, &buffer)?;
        let entrypoint = elf.header.e_entry as u32;

        Ok(Self {
            code_segment,
            data_segment,
            entrypoint,
        })
    }

    // Parses the Elf, extracting the code and data segments.
    // Fails if there are not exactly two loadable segments, one read-execute and one read-write.
    fn parse_segments(elf: &Elf, data: &[u8]) -> io::Result<(Segment, Segment)> {
        let mut segments: Vec<_> = elf
            .program_headers
            .iter()
            .filter(|segment| segment.p_type == PT_LOAD)
            .collect();

        segments.sort_by_key(|segment| segment.p_flags);

        if segments.len() != 2 {
            return Err(io::Error::new(io::ErrorKind::Other, "Expected exactly 2 loadable segments"));
        }

        let flags: Vec<_> = segments.iter().map(|segment| segment.p_flags).collect();

        let rx = PF_R | PF_X;
        let rw = PF_R | PF_W;
        if flags != vec![rx, rw] {
            return Err(io::Error::new(io::ErrorKind::Other, "Expected exactly one read-execute and one read-write segment"));
        }

        let code_start = segments[0].p_offset as usize;
        let code_size = segments[0].p_filesz as usize;
        let code_seg = Segment::new(segments[0], &data[code_start..code_start + code_size]);
        let data_start = segments[1].p_offset as usize;
        let data_size = segments[1].p_filesz as usize;
        let data_seg = Segment::new(segments[1], &data[data_start..data_start + data_size]);

        println!("{:?} {:?} {:?} {:?} ", code_start, code_size, data_start, data_size); // TODO: remove

        Ok((code_seg, data_seg))
    }
}
