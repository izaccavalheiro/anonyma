//! `anonyma._native`: the PyO3 module under the Python package `anonyma`.
//!
//! Detection, anonymization and tokens take and return native Python strings
//! and tuples (no JSON on the hot path), and release the GIL while the core
//! scans. Presets, validators and receipts go through the JSON API of
//! `anonyma-ffi`, which the conformance suite tests. Offsets are code points,
//! as Python indexes strings.

use anonyma_core::offsets::OffsetMap;
use anonyma_core::{
    detokenize as core_detokenize, AnonymaEngine, Category, Error, InMemoryVault, Match, Preset,
    StrategySpec, Vault,
};
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

create_exception!(
    _native,
    AnonymaError,
    PyException,
    "An argument anonyma cannot use, or an operation it cannot perform."
);
create_exception!(
    _native,
    UnsupportedCategoriesError,
    AnonymaError,
    "Categories the Rust core does not detect in full yet; pass allow_partial=True to accept partial detection."
);

fn to_py(error: Error) -> PyErr {
    match &error {
        Error::UnsupportedCategories(_) => UnsupportedCategoriesError::new_err(error.to_string()),
        _ => AnonymaError::new_err(error.to_string()),
    }
}

fn parse_strategy(json: &str) -> PyResult<StrategySpec> {
    let value: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| AnonymaError::new_err(format!("strategy is not JSON: {e}")))?;
    anonyma_ffi::api::strategy_from(&value).map_err(AnonymaError::new_err)
}

/// (category, value, start, end, confidence), offsets in code points.
type MatchTuple = (String, String, usize, usize, f64);

fn tuples(text: &str, matches: &[Match]) -> Vec<MatchTuple> {
    let offsets = OffsetMap::new(text);
    matches
        .iter()
        .map(|m| {
            (
                m.category.as_str().to_string(),
                m.value.clone(),
                offsets.code_points(m.start),
                offsets.code_points(m.end),
                m.confidence,
            )
        })
        .collect()
}

/// A token vault: each token and the original value it stands for.
#[pyclass(name = "Vault", module = "anonyma._native")]
#[derive(Default)]
struct PyVault {
    inner: InMemoryVault,
}

#[pymethods]
impl PyVault {
    #[new]
    #[pyo3(signature = (entries=None))]
    fn new(entries: Option<Vec<(String, String)>>) -> PyResult<Self> {
        let inner = InMemoryVault::from_entries(entries.unwrap_or_default()).map_err(to_py)?;
        Ok(PyVault { inner })
    }

    fn store(&mut self, token: &str, value: &str) -> PyResult<()> {
        self.inner.store(token, value).map_err(to_py)
    }

    fn retrieve(&self, token: &str) -> Option<String> {
        self.inner.retrieve(token)
    }

    fn delete(&mut self, token: &str) -> bool {
        self.inner.delete(token)
    }

    fn clear(&mut self) {
        self.inner.clear();
    }

    fn entries(&self) -> Vec<(String, String)> {
        self.inner.entries().to_vec()
    }

    /// (text, restored, unresolved)
    fn restore(&self, text: &str) -> (String, usize, Vec<String>) {
        let out = anonyma_core::restore(text, &self.inner);
        (out.text, out.restored, out.unresolved)
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    fn __contains__(&self, token: &str) -> bool {
        self.inner.retrieve(token).is_some()
    }

    fn __repr__(&self) -> String {
        // Never show the values: they are the personal data.
        format!("Vault(<{} tokens>)", self.inner.len())
    }
}

/// A configured engine of the Rust core.
#[pyclass(name = "Engine", module = "anonyma._native", frozen)]
struct PyEngine {
    inner: AnonymaEngine,
}

#[pymethods]
impl PyEngine {
    #[new]
    #[pyo3(signature = (*, presets=None, categories=None, rules=None, default_strategy=None, aggressive=false, strict=false, allow_partial=false))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        presets: Option<Vec<String>>,
        categories: Option<Vec<String>>,
        rules: Option<Vec<(String, String)>>,
        default_strategy: Option<String>,
        aggressive: bool,
        strict: bool,
        allow_partial: bool,
    ) -> PyResult<Self> {
        let mut builder = AnonymaEngine::builder()
            .aggressive(aggressive)
            .strict(strict)
            .allow_partial(allow_partial);
        for name in presets.unwrap_or_default() {
            builder = builder.preset(name.parse::<Preset>().map_err(to_py)?);
        }
        if let Some(names) = categories {
            let parsed = names
                .iter()
                .map(|name| name.parse::<Category>())
                .collect::<Result<Vec<_>, _>>()
                .map_err(to_py)?;
            builder = builder.categories(parsed);
        }
        for (category, strategy) in rules.unwrap_or_default() {
            let category = category.parse::<Category>().map_err(to_py)?;
            builder = builder.rule(category, parse_strategy(&strategy)?);
        }
        if let Some(strategy) = default_strategy {
            builder = builder.default_strategy(parse_strategy(&strategy)?);
        }
        Ok(PyEngine {
            inner: builder.build().map_err(to_py)?,
        })
    }

    fn undetected(&self) -> Vec<String> {
        self.inner
            .undetected()
            .iter()
            .map(|c| c.as_str().to_string())
            .collect()
    }

    fn detect(&self, py: Python<'_>, text: &str) -> Vec<MatchTuple> {
        let engine = &self.inner;
        py.detach(|| tuples(text, &engine.detect(text)))
    }

    /// (text, matches)
    fn anonymize(&self, py: Python<'_>, text: &str) -> PyResult<(String, Vec<MatchTuple>)> {
        let engine = &self.inner;
        py.detach(|| {
            engine
                .anonymize(text)
                .map(|out| (out.text, tuples(text, &out.matches)))
        })
        .map_err(to_py)
    }

    /// (text, mapping)
    fn tokenize(&self, py: Python<'_>, text: &str) -> (String, Vec<(String, String)>) {
        let engine = &self.inner;
        py.detach(|| {
            let out = engine.tokenize(text);
            (out.text, out.mapping)
        })
    }

    /// (text, [(token, category)])
    fn shield(
        &self,
        text: &str,
        mut vault: PyRefMut<'_, PyVault>,
    ) -> PyResult<(String, Vec<(String, String)>)> {
        let out = self.inner.shield(text, &mut vault.inner).map_err(to_py)?;
        let tokens = out
            .tokens
            .into_iter()
            .map(|(token, category)| (token, category.as_str().to_string()))
            .collect();
        Ok((out.text, tokens))
    }
}

/// The JSON API of the core: `call(op, input_json)` returns
/// `{"ok": ...}` or `{"error": ...}`.
#[pyfunction]
fn call(op: &str, input_json: &str) -> String {
    anonyma_ffi::api::call_json(op, input_json)
}

/// Restore classic tokens: (text, replaced, unresolved).
#[pyfunction]
fn detokenize(text: &str, mapping: Vec<(String, String)>) -> (String, usize, Vec<String>) {
    let out = core_detokenize(text, &mapping);
    (out.text, out.restored, out.unresolved)
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("CORE_VERSION", anonyma_core::VERSION)?;
    m.add("AnonymaError", m.py().get_type::<AnonymaError>())?;
    m.add(
        "UnsupportedCategoriesError",
        m.py().get_type::<UnsupportedCategoriesError>(),
    )?;
    m.add_class::<PyVault>()?;
    m.add_class::<PyEngine>()?;
    m.add_function(wrap_pyfunction!(call, m)?)?;
    m.add_function(wrap_pyfunction!(detokenize, m)?)?;
    Ok(())
}
