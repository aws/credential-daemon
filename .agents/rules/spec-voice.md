---
name: spec-voice
description: Specs describe the system's desired end state in durable voice — not the change that produced it
---

# Spec Voice

A spec (`requirements.md`, `design.md`) describes the **desired state of the system**, in
durable, present-tense voice — as if the system already works this way. It is read long
after the change that introduced it, by someone who does not know or care which PR touched
which file. Write it for that reader.

## The rule

- **Present tense, desired state.** "The daemon owns the keystore and is the only process
  that opens it." Not "Three client sites open the keystore today; this PR moves them."
- **No change narrative.** Drop "today / currently / previously", "replaced by", "we now",
  "Fate: deleted", before/after tables, and migration play-by-play. If a sentence only makes
  sense to someone watching the diff, it does not belong in the spec.
- **Refactor rationale goes in the PR description.** Why the change was made, what it
  replaced, and how it was sequenced are review context, not the durable record. *Design*
  rationale — why the system is shaped this way, alternatives considered and rejected — does
  belong in `design.md`, phrased as properties of the system, not of the edit.

## Why

The spec outlives the PR. Change-narrative rots the moment it merges: "today the client opens
storage" is false as soon as it doesn't, and a reader can no longer tell whether the spec
describes the system or its history. Durable voice stays true, and keeps the spec diffable
against the code it governs (see `AGENTS.md` → Spec Coherence).

## Quick test

Read a sentence with no knowledge of the PR. If it still describes how the system behaves,
it is durable. If it only means something relative to a change in flight, move it to the PR
description or cut it.
