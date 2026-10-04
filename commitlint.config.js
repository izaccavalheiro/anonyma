/**
 * Commit messages follow Conventional Commits (see CONTRIBUTING.md).
 * Line-length limits on the body and the footer are off: both carry links and
 * trailers that cannot be wrapped.
 */
export default {
  extends: ["@commitlint/config-conventional"],
  rules: {
    "body-max-line-length": [0],
    "footer-max-line-length": [0],
  },
};
