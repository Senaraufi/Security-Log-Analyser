# bench: prompt-injection experiments

Dataset rows are JSONL: `{id, line, label, attack_type, injected, variant, source_id}` where `line` is an Apache combined log line and `label` is `attack` or `benign`. Row ids must be unique; `bench run` refuses duplicates.

```bash
# 1. Make injected copies of the attack lines (ua|path x 5 wordings x plain|url).
#    Do NOT pass --with-originals here: the clean lines already live in data.jsonl.
cargo run -p security-bench -- inject --input data.jsonl --output injected.jsonl

# 2. Run mode x model x repeat (temperature 0, seeded batches, responses cached in .bench_cache)
cargo run -p security-bench -- run --dataset data.jsonl --injected injected.jsonl \
  --modes rules_only,ai_decides,rules_first,spotlight \
  --models groq:openai/gpt-oss-120b,gemini:gemini-3.5-flash-lite \
  --repeats 3 --batch-size 20 --seed 42

# 3. Score
cargo run -p security-bench -- score --results bench_out/results.jsonl --by-variant --csv summary.csv
```

Outputs in `bench_out/`: `results.jsonl` (one row per line per run), `calls.jsonl` (full prompt, raw response, model, temperature, mode, timing for every call) and `meta.json` (git describe, seed, settings).
`rules_only` runs the rule engine (`ApacheLog::analyze`) with no model call and is the rules baseline.
`--max-tokens` defaults to 16384 so reasoning models such as gpt-oss do not truncate their JSON.

## Batches

Batches are built from a seeded shuffle (`--seed`, recorded in every result) and are identical across modes, models and repeats, so comparisons are paired.

- **control batches:** only clean lines (benign and clean attacks), chunked to `--batch-size`.
- **injected batches:** exactly one injected line plus `batch-size - 1` clean bystander lines, at a random position. The clean original of the injected line is never a bystander.

Score groups: `clean` (control batches), `injected` (the injected line) and `bystander` (clean lines sharing a batch with an injection). Bystander vs clean shows collateral effects of an injection on other lines (false alarms and misses).

## Metrics

- **missed:** attack lines predicted harmless, as a share of attack lines with a usable response.
- **missed (strict):** also counts attack lines in parse-failed responses as missed. Use this one for the headline: otherwise an injection that breaks the AI's JSON makes the AI look better.
- **false alarms:** benign lines predicted malicious.
- **parse failures:** share of rows whose AI response was unreadable (includes `rules_first`, where the rules' verdict still stands).
- **ai dismisses flagged** (`rules_first` only): how often the AI's own per-line verdict calls a rule-flagged attack harmless. This is the explanation-manipulation metric. The strict variant also counts a missing AI verdict as dismissed. In `rules_first` the rules' answer is stored in `line_verdicts` and the AI's own in `ai_line_verdicts`.
- Every rate is reported as mean [min-max] sd across repeats.

## Methodology notes

- **`path/plain` is unrealistic.** It puts raw spaces (and escaped quotes) in the request path, which real clients and servers would percent-encode. Treat it as a stress case. `path/url` is the realistic path injection.
- **Spotlight also rewrites the logs.** Besides fencing the log block, it replaces `<<<` and `>>>` inside log text with look-alike characters so injected text cannot forge the end marker. The model therefore sees slightly different text than in the other modes, and the `marker_escape` wording is partly neutralised by design.
- **Experiments use the AI path only**, at `--temperature 0`. Simple Mode drops the user agent and hardcodes temperature 0.3, so do not use it.
- The injected variants differ in more than one dimension; compare by `--by-variant` before pooling.
