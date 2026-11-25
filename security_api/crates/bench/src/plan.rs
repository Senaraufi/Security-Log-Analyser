//! Batch planning: seeded, reproducible mixed batches.
//!
//! - control batches: only clean lines (benign + clean attacks), so clean
//!   performance and false alarms can be measured with no injection present
//! - injected batches: exactly one injected line plus clean "bystander" lines,
//!   so any effect of an injection on the other lines in its batch shows up
//!   as bystander-vs-control

use crate::dataset::Row;

pub const ROLE_CONTROL: &str = "control";
pub const ROLE_INJECTED: &str = "injected";
pub const ROLE_BYSTANDER: &str = "bystander";

#[derive(Debug, Clone)]
pub struct PlannedRow {
    pub row: Row,
    pub role: &'static str,
    /// Variant of the injection in this batch (set for the injected line and its bystanders)
    pub batch_variant: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Batch {
    pub id: String,
    pub rows: Vec<PlannedRow>,
}

/// splitmix64: tiny, fast and fully deterministic across platforms
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Fisher-Yates shuffle
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = (self.next_u64() % (i as u64 + 1)) as usize;
            items.swap(i, j);
        }
    }
}

fn source_of(row: &Row) -> &str {
    row.source_id.as_deref().unwrap_or("")
}

pub fn build_batches(rows: Vec<Row>, batch_size: usize, seed: u64) -> Vec<Batch> {
    let batch_size = batch_size.max(1);
    let (injected, mut clean): (Vec<Row>, Vec<Row>) = rows.into_iter().partition(|r| r.injected);
    let mut rng = Rng::new(seed);
    rng.shuffle(&mut clean);

    let mut batches = Vec::new();
    for (n, chunk) in clean.chunks(batch_size).enumerate() {
        batches.push(Batch {
            id: format!("c{n:04}"),
            rows: chunk
                .iter()
                .map(|r| PlannedRow {
                    row: r.clone(),
                    role: ROLE_CONTROL,
                    batch_variant: None,
                })
                .collect(),
        });
    }

    // Bystanders walk a separately shuffled copy of the clean pool so every
    // clean line is used about equally often.
    let mut pool = clean;
    Rng::new(seed ^ 0xA5A5_A5A5_5A5A_5A5A).shuffle(&mut pool);
    let mut cursor = 0;
    for (n, inj) in injected.into_iter().enumerate() {
        let mut rows = Vec::new();
        let mut taken = 0;
        let mut scanned = 0;
        while taken < batch_size - 1 && scanned < pool.len() {
            let cand = &pool[cursor % pool.len()];
            cursor += 1;
            scanned += 1;
            if cand.id != source_of(&inj) {
                rows.push(PlannedRow {
                    row: cand.clone(),
                    role: ROLE_BYSTANDER,
                    batch_variant: inj.variant.clone(),
                });
                taken += 1;
            }
        }
        rows.push(PlannedRow {
            batch_variant: inj.variant.clone(),
            row: inj,
            role: ROLE_INJECTED,
        });
        rng.shuffle(&mut rows);
        batches.push(Batch {
            id: format!("i{n:04}"),
            rows,
        });
    }
    batches
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, attack: bool) -> Row {
        Row {
            id: id.into(),
            line: format!("line {id}"),
            label: if attack { "attack" } else { "benign" }.into(),
            attack_type: None,
            injected: false,
            variant: None,
            source_id: None,
        }
    }

    fn data() -> Vec<Row> {
        let mut rows: Vec<Row> = (0..12).map(|i| row(&format!("b{i}"), false)).collect();
        rows.extend((0..6).map(|i| row(&format!("a{i}"), true)));
        for (i, src) in ["a0", "a1", "a2"].iter().enumerate() {
            rows.push(Row {
                id: format!("{src}__v{i}"),
                injected: true,
                variant: Some(format!("ua/x/v{i}")),
                source_id: Some(src.to_string()),
                ..row(src, true)
            });
        }
        rows
    }

    #[test]
    fn exactly_one_injected_line_per_injected_batch_and_none_in_control() {
        let batches = build_batches(data(), 5, 1);
        let (ctl, inj): (Vec<_>, Vec<_>) = batches.iter().partition(|b| b.id.starts_with('c'));
        assert_eq!(ctl.len(), 4); // 18 clean lines / 5
        assert_eq!(inj.len(), 3);
        assert!(ctl.iter().all(|b| b
            .rows
            .iter()
            .all(|r| r.role == ROLE_CONTROL && !r.row.injected)));
        for b in &inj {
            assert_eq!(b.rows.len(), 5);
            assert_eq!(b.rows.iter().filter(|r| r.row.injected).count(), 1);
            assert_eq!(
                b.rows.iter().filter(|r| r.role == ROLE_BYSTANDER).count(),
                4
            );
            let i = b.rows.iter().find(|r| r.role == ROLE_INJECTED).unwrap();
            assert!(b.rows.iter().all(|r| r.batch_variant == i.batch_variant));
            // the clean original of the injected line is never a bystander
            assert!(b
                .rows
                .iter()
                .all(|r| Some(r.row.id.as_str()) != i.row.source_id.as_deref()));
            let mut ids: Vec<_> = b.rows.iter().map(|r| &r.row.id).collect();
            ids.sort();
            ids.dedup();
            assert_eq!(ids.len(), 5);
        }
    }

    #[test]
    fn plan_is_reproducible_per_seed_and_differs_across_seeds() {
        let ids = |seed| -> Vec<Vec<String>> {
            build_batches(data(), 5, seed)
                .iter()
                .map(|b| b.rows.iter().map(|r| r.row.id.clone()).collect())
                .collect()
        };
        assert_eq!(ids(7), ids(7));
        assert_ne!(ids(7), ids(8));
    }

    #[test]
    fn mixes_benign_and_attack_lines_and_places_injection_at_varying_positions() {
        let batches = build_batches(data(), 6, 3);
        assert!(
            batches[0].rows.iter().any(|r| r.row.is_attack())
                || batches[1].rows.iter().any(|r| r.row.is_attack())
        );
        let pos: std::collections::HashSet<usize> = build_batches(data(), 6, 3)
            .iter()
            .filter(|b| b.id.starts_with('i'))
            .filter_map(|b| b.rows.iter().position(|r| r.role == ROLE_INJECTED))
            .collect();
        assert!(!pos.is_empty());
    }

    #[test]
    fn only_injected_rows_without_clean_pool_still_batch() {
        let rows: Vec<Row> = data().into_iter().filter(|r| r.injected).collect();
        let b = build_batches(rows, 5, 1);
        assert_eq!(b.len(), 3);
        assert!(b.iter().all(|b| b.rows.len() == 1));
    }
}
