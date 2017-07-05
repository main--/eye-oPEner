use std::io::Write;

use plist::{Plist, Error};
use plist::xml::EventWriter;

pub fn ser_plist<W: Write>(plist: Plist, write: W) -> Result<(), Error> {
    let mut writer = EventWriter::new(write);
    for event in plist.into_events() {
        writer.write(&event)?;
    }
    Ok(())
}
