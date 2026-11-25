// The ONLY place neutral interface words live (debate 11): button labels, tab names, field names
// that claim nothing. Anything that says something about the evidence (a state, a certainty, a
// result, a count) comes from Python. tests/test_dashboard_frontend.py greps all front-end source
// for banned claim words.
export const T = {
  appName: "Analyst Lab",
  tabs: { live: "Live", story: "Story", twoMachines: "Two machines", twin: "Evil twin", coverage: "Coverage", scoreboard: "How we know it works" },
  play: "Play the story",
  fit: "Fit",
  event: "Event",
  time: "Time",
  record: "Record",
  machine: "Machine",
  dataset: "Dataset",
  file: "Recording",
  commit: "version",
  licence: "Licence",
  chosen: "Why this recording",
  alertFor: "Alert",
  showRecord: "Show the recorded event",
  hideRecord: "Hide the recorded event",
  details: "How this was worked out",
  source: "Source",
  to: "to",
  moreDetails: "Details",
  runTitle: "Test machine",
  runS1: "Run S1 in the test machine",
  elapsed: "Elapsed",
  loading: "Loading…",
  comingSoon: "This screen is being built.",
  errorPrefix: "Could not load:",
} as const;
