# Write-up template: "I tested an LLM app against the OWASP LLM Top 10"

The tool does not produce real-model results by itself. Fill every bracket with numbers from your own runs; do not publish the demo-target scores as if they were a real model's.

1. **Target** - [model, system prompt summary, guardrails, RAG/tools yes/no]. Planted canary: [yes].
2. **Method** - PromptGuard Lab v[x], [N] tests, [k] repeats, [m] mutations, judge [on/off, model].
3. **Baseline result** - score [..]/100, grade [..]. Table: category, failures, attack success rate.
4. **Three findings** - for each: attack text, the response (redacted), why it worked, OWASP id, fix.
5. **Fix and re-test** - what you changed (prompt, input filter, output filter, tool gating), score before -> after using the "compare two system prompts" view, which tests flipped.
6. **Multi-turn and RAG results** - these usually beat single-message defences; say what you saw.
7. **Detector accuracy** - run `npm run eval`, add [N] real responses you labelled by hand, report precision/recall.
8. **Limits** - false negatives you found, what the tool cannot test.
9. **CI gate** - paste your workflow and a failing-then-passing run.
