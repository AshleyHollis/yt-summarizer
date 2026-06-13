# OpenClaw YouTube Discord Workflow

This workflow lets OpenClaw use Discord as the conversational control surface for
YT Summarizer.

## Discord Channel

Use one text channel:

- `#youtube-library` - search YouTube, submit transcript-only ingestion, ask questions,
  and create Obsidian knowledge notes.

OpenClaw should not create separate watch-next, recommendation, or playlist-curation
channels for this workflow.

## MCP Configuration

OpenClaw should run the `yt-summarizer-mcp` server with:

- `YT_SUMMARIZER_API_URL` pointing at the YT Summarizer API.
- `YT_SUMMARIZER_API_KEY` set from the existing secret store.

Do not paste API keys, Google credentials, or Obsidian vault paths into Discord.

## Default Behavior

- Searching YouTube does not ingest anything.
- Ingesting a video or batch defaults to `transcript_only`.
- Full analysis is allowed only when the user explicitly asks for it.
- Raw transcripts stay in YT Summarizer storage.
- Obsidian receives curated Markdown notes, not transcript dumps.

## Expected OpenClaw Commands

Examples users can type in `#youtube-library`:

```text
Search YouTube for Mark Wildman heavy club shoulder mobility.

Add this video transcript-only:
https://www.youtube.com/watch?v=...

Download transcripts for these links:
https://www.youtube.com/watch?v=...
https://www.youtube.com/watch?v=...

Ask my YouTube library:
What does Mark Wildman say about heavy club programming?

Extract useful knowledge from this video into Obsidian.
Use Resources/Training/YouTube as the PARA destination.
```

## Tool Usage Rules

OpenClaw should use the MCP tools as follows:

- `search_youtube` to find candidate videos.
- `ingest` for one selected video; leave `processing_mode` unset for transcript-only.
- `ingest_batch` for selected Discord link lists.
- `ingest_channel_sample` only for canaries or small research pulls.
- `get_job_status` until transcription completes.
- `ask` for Q&A over the existing transcript library.
- `get_video` and `get_segments` when inspecting specific transcript ranges.
- `extract_knowledge` to create a PARA-ready Markdown note.

## Obsidian/PARA Contract

The `extract_knowledge` tool returns:

- `title`
- `para_path`
- `markdown`
- `tags`
- `sources`

OpenClaw is responsible for writing `markdown` into the Obsidian vault at the
suggested `para_path`, or at a user-approved alternative path.

Default PARA destinations:

- `Projects/...` for active archive/research jobs.
- `Areas/...` for ongoing responsibilities.
- `Resources/YouTube/...` for durable topic/channel/person knowledge.
- `Archives/...` for completed or inactive material.

## Safety

- Do not expose new public endpoints for Discord.
- Do not automate YouTube watch history or recommendations in this workflow.
- Do not download transcripts unless the user asks to add/import videos.
- Do not run full AI features unless the user explicitly requests them.
