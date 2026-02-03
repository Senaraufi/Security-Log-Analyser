# Migration Guide: Groq Analyzer → Multi-Provider LLM Analyzer

This guide helps you migrate from the legacy `analyzer-groq` to the new `analyzer-llm` with multi-provider support.

## Why Migrate?

The new `analyzer-llm` crate provides:
- **Multi-provider support**: OpenAI, Anthropic, Groq, and Gemini
- **Easy provider switching**: Change providers without code changes
- **Better error handling**: User-friendly error messages and suggestions
- **Health check endpoint**: Verify configuration before analysis
- **Future-proof**: Built on `rig-core` for ongoing provider support

## Quick Migration (5 minutes)

### Step 1: Update Environment Variables

**Old configuration (`.env`):**
```env
GROQ_API_KEY=gsk_your-groq-api-key-here
GROQ_MODEL=llama-3.3-70b-versatile
```

**New configuration (`.env`):**
```env
# Multi-provider LLM configuration
LLM_PROVIDER=groq
LLM_MODEL=llama-3.1-70b-versatile
LLM_TEMPERATURE=0.3
LLM_MAX_TOKENS=4096

# Your Groq API key (same as before)
GROQ_API_KEY=gsk_your-groq-api-key-here
```

### Step 2: Test Configuration

Check that your configuration is valid:

```bash
curl http://localhost:3000/api/llm-health
```

Expected response:
```json
{
  "status": "ok",
  "configured": true,
  "provider": "groq",
  "model": "llama-3.1-70b-versatile"
}
```

### Step 3: Update API Calls (if using programmatically)

**Old endpoint:**
```bash
POST /api/analyze-with-ai
```

**New endpoint:**
```bash
POST /api/analyze-with-llm
```

The frontend has been automatically updated to use the new endpoint.

## Switching to a Different Provider

Want to try OpenAI or Anthropic instead of Groq?

### Using OpenAI (GPT-4o)

```env
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o
OPENAI_API_KEY=sk-your-openai-api-key-here
```

### Using Anthropic (Claude)

```env
LLM_PROVIDER=anthropic
LLM_MODEL=claude-sonnet-4-20250514
ANTHROPIC_API_KEY=sk-ant-your-anthropic-api-key-here
```

No code changes required - just update `.env` and restart!

## Deprecation Timeline

- **Now**: Both endpoints work (`/api/analyze-with-ai` and `/api/analyze-with-llm`)
- **Next release**: `/api/analyze-with-ai` will show deprecation warnings
- **Future release**: `/api/analyze-with-ai` will be removed

## Troubleshooting

### "API key not found" error

Ensure you've set the correct environment variable:
- For Groq: `GROQ_API_KEY`
- For OpenAI: `OPENAI_API_KEY`
- For Anthropic: `ANTHROPIC_API_KEY`

### "Invalid provider" error

Check that `LLM_PROVIDER` is one of: `openai`, `anthropic`, `groq`, `gemini`

### Different results between old and new analyzer

The new analyzer uses improved prompts and may provide more detailed analysis. This is expected and intentional.

## Need Help?

- See `LLM_CONFIG.md` for detailed configuration options
- Check the health endpoint: `GET /api/llm-health`
- Review error messages - they include helpful suggestions

## Rollback (if needed)

If you need to temporarily use the old endpoint:

1. Keep your old `GROQ_API_KEY` and `GROQ_MODEL` in `.env`
2. Use `/api/analyze-with-ai` endpoint
3. The old analyzer will continue to work until deprecated

However, we recommend migrating to the new system for better features and ongoing support.
