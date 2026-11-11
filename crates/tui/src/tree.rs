//! Katman ağacını görünür satırlara düzleştirme ve hex vurgu hesabı.

use std::collections::HashSet;
use std::hash::BuildHasher;
use std::ops::Range;

use pakiz_dissect::{Dissection, Field};

/// Ağaçta düğüm yolu: `[katman, çocuk, çocuk, ...]`.
pub type NodePath = Vec<usize>;

/// Ağaç panelinde görünen tek satır.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeRow {
    pub depth: usize,
    pub label: String,
    pub path: NodePath,
    pub has_children: bool,
    pub expanded: bool,
    pub offset: usize,
    pub len: usize,
    pub malformed: bool,
}

/// Yalnızca açık düğümlerin çocuklarını içeren düz satır listesi.
#[must_use]
pub fn flatten<S: BuildHasher>(d: &Dissection, expanded: &HashSet<NodePath, S>) -> Vec<TreeRow> {
    let mut out = Vec::new();
    for (i, l) in d.layers.iter().enumerate() {
        walk(&l.fields, &[i], 0, expanded, &mut out);
    }
    out
}

fn walk<S: BuildHasher>(
    f: &Field,
    path: &[usize],
    depth: usize,
    ex: &HashSet<NodePath, S>,
    out: &mut Vec<TreeRow>,
) {
    let open = ex.contains(path);
    out.push(TreeRow {
        depth,
        label: f.label.to_string(),
        path: path.to_vec(),
        has_children: !f.children.is_empty(),
        expanded: open,
        offset: f.offset,
        len: f.len,
        malformed: f.malformed,
    });
    if open {
        for (ci, c) in f.children.iter().enumerate() {
            let mut p = path.to_vec();
            p.push(ci);
            walk(c, &p, depth + 1, ex, out);
        }
    }
}

/// Seçili alanın vurgulanacak bayt aralığı, veri uzunluğuna kırpılmış.
#[must_use]
pub fn highlight_range(offset: usize, len: usize, data_len: usize) -> Option<Range<usize>> {
    let start = offset.min(data_len);
    let end = offset.saturating_add(len).min(data_len);
    (start < end).then_some(start..end)
}
