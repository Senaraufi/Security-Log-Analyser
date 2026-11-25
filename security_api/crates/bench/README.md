# bench: prompt-injection experiments

Dataset rows are JSONL: `{id, line, label, attack_type, injected, variant}` where `line` is an Apache combined log line and `label` is `attack` or `benign`.

```bash
# 1. Make injected copies of the attack lines (ua|path x 5 wordings x plain|url)
cargo run -p security-bench -- inject --input data.jsonl --output injected.jsonl --with-originals
cat data.jsonl injected.jsonl > all.jsonl

# 2. Run mode x model x repeat (temperature 0, responses cached in .bench_cache)
cargo run -p security-bench -- run --dataset all.jsonl \
  --modes rules_only,ai_decides,rules_first,spotlight \
  --models groq:openai/gpt-oss-120b,anthropic:claude-sonnet-4-20250514 \
  --repeats 3 --batch-size 20

# 3. Score (missed attacks, false alarms, parse failures; mean [min-max] sd across repeats)
cargo run -p security-bench -- score --results bench_out/results.jsonl --by-variant --csv summary.csv
```

Outputs in `bench_out/`: `results.jsonl` (one row per line per run) and `calls.jsonl` (full prompt, raw response, model, temperature, mode, timing for every call).
`rules_only` runs the rule engine (`ApacheLog::analyze`) with no model call and is the rules baseline.
