use std::io::Result;

fn main() -> Result<()> {
    // Compile protobuf definitions
    tonic_build::compile_protos("proto/ghostd.proto")?;
    println!("cargo:rerun-if-changed=proto/ghostd.proto");
    Ok(())
}
