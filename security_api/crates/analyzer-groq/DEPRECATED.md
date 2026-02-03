# ⚠️ DEPRECATED: analyzer-groq

This crate is **deprecated** and will be removed in a future release.

## Migration Required

Please migrate to the new **`analyzer-llm`** crate which provides:

- ✅ Multi-provider support (OpenAI, Anthropic, Groq, Gemini)
- ✅ Easy provider switching via environment variables
- ✅ Better error handling with helpful suggestions
- ✅ Health check endpoint
- ✅ Built on `rig-core` for future-proof provider support

## Quick Migration

See [`MIGRATION.md`](../../MIGRATION.md) in the workspace root for a complete migration guide.

**TL;DR:**

1. Update your `.env`:
   ```env
   LLM_PROVIDER=groq
   LLM_MODEL=llama-3.1-70b-versatile
   GROQ_API_KEY=your-key-here
   ```

2. Use the new endpoint: `/api/analyze-with-llm` (frontend already updated)

3. That's it! No code changes needed.

## Timeline

- **Current**: Both endpoints work (`/api/analyze-with-ai` and `/api/analyze-with-llm`)
- **Next release**: Deprecation warnings will be shown
- **Future release**: This crate and `/api/analyze-with-ai` will be removed

## Questions?

See the full documentation:
- [`LLM_CONFIG.md`](../analyzer-llm/LLM_CONFIG.md) - Configuration guide
- [`MIGRATION.md`](../../MIGRATION.md) - Migration guide
