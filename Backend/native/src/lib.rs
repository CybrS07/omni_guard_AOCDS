use pyo3::prelude::*;

// Each part keeps its own .rs file next to its Python code. Enable when written:
// #[path = "../../security/native.rs"]                  mod security;
// #[path = "../../fyp1/modules/malware/native.rs"]      mod malware;
// #[path = "../../fyp1/modules/stego/native.rs"]        mod stego;
// #[path = "../../fyp2/modules/firewall/native.rs"]     mod firewall;
// #[path = "../../fyp2/modules/registry_backup/native.rs"] mod registry_backup;

#[pyfunction]
fn ping() -> &'static str {
    "omniguard_native ok"
}

#[pymodule]
fn omniguard_native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(ping, m)?)?;
    Ok(())
}
