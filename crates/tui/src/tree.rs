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

/// Her satırın kılavuz öneki (`│  ├─ `); kök (katman) satırlarında boş.
/// `guides` = [`crate::IconSet::guides`] (orta dal, son dal, devam, boş).
#[must_use]
pub fn guide_prefixes(rows: &[TreeRow], guides: [&str; 4]) -> Vec<String> {
    let [mid, last, cont, blank] = guides;
    // Geriye doğru: her satır kardeşlerinin sonuncusu mu.
    let mut is_last = vec![true; rows.len()];
    let mut seen: Vec<bool> = Vec::new();
    for (i, r) in rows.iter().enumerate().rev() {
        if seen.len() <= r.depth {
            seen.resize(r.depth + 1, false);
        }
        is_last[i] = !seen[r.depth];
        seen[r.depth] = true;
        seen.truncate(r.depth + 1);
    }
    // İleriye: üst atalar sonuncuysa boşluk, değilse dikey çizgi.
    let mut anc: Vec<bool> = Vec::new();
    let mut out = Vec::with_capacity(rows.len());
    for (r, &last_sibling) in rows.iter().zip(&is_last) {
        anc.truncate(r.depth);
        let mut p = String::new();
        if r.depth > 0 {
            for &al in anc.iter().skip(1) {
                p.push_str(if al { blank } else { cont });
            }
            p.push_str(if last_sibling { last } else { mid });
        }
        anc.push(last_sibling);
        out.push(p);
    }
    out
}
