import type * as Preset from "@docusaurus/preset-classic";
import type { Config } from "@docusaurus/types";
import { themes as prismThemes } from "prism-react-renderer";

const repository = "https://github.com/izaccavalheiro/anonyma";

/**
 * The site loads one script from another origin: the Monoid analytics tracker
 * (ANALYTICS_ORIGIN), which records page views and, with autotrack, clicks.
 * The policy allows that origin for scripts and connections and nothing else:
 * no other origin can be loaded or contacted, and no form can be submitted.
 * Docusaurus inlines a small script that sets the colour mode before the page
 * paints, hence 'unsafe-inline' for scripts. The playground's own code opens
 * no connection. `npm run check:privacy` checks this policy.
 *
 * Applied to the production build only: the development server needs a
 * WebSocket for hot reloading, and local visits are not recorded.
 */
const ANALYTICS_ORIGIN = "https://api.monoid.website";

const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline' ${ANALYTICS_ORIGIN}`,
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data:",
  "font-src 'self' data:",
  `connect-src ${ANALYTICS_ORIGIN}`,
  "form-action 'none'",
  "frame-src 'none'",
  "object-src 'none'",
  "base-uri 'self'",
].join("; ");

const production = process.env["NODE_ENV"] === "production";

const config: Config = {
  title: "anonyma",
  tagline:
    "Find and anonymize personal data in TypeScript — zero dependencies, in your process, on the edge.",
  favicon: "img/logo.svg",

  url: "https://izaccavalheiro.github.io",
  baseUrl: "/anonyma/",
  organizationName: "izaccavalheiro",
  projectName: "anonyma",
  trailingSlash: false,

  onBrokenLinks: "throw",
  onBrokenAnchors: "throw",
  markdown: {
    // .md files are CommonMark, so the repository's own Markdown is used as it is;
    // .mdx files may use components.
    format: "detect",
    hooks: { onBrokenMarkdownLinks: "throw" },
  },

  i18n: { defaultLocale: "en", locales: ["en"] },

  headTags: production
    ? [
        {
          tagName: "meta",
          attributes: { "http-equiv": "Content-Security-Policy", content: CONTENT_SECURITY_POLICY },
        },
        { tagName: "meta", attributes: { name: "referrer", content: "no-referrer" } },
        {
          tagName: "script",
          attributes: {
            async: true,
            defer: true,
            src: `${ANALYTICS_ORIGIN}/tracker.min.js`,
            "data-site-id": "oi4iiasquc",
            "data-autotrack": "true",
          },
        },
      ]
    : [],

  presets: [
    [
      "classic",
      {
        docs: {
          sidebarPath: "./sidebars.ts",
          editUrl: `${repository}/edit/main/website/`,
          showLastUpdateTime: false,
        },
        blog: {
          showReadingTime: true,
          blogTitle: "anonyma blog",
          blogDescription: "Releases, guides and notes on privacy engineering with anonyma.",
          feedOptions: { type: ["rss", "atom"], xslt: true },
          onInlineTags: "throw",
          onInlineAuthors: "throw",
          onUntruncatedBlogPosts: "throw",
        },
        theme: { customCss: "./src/css/custom.css" },
        sitemap: { changefreq: "weekly" },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    colorMode: { respectPrefersColorScheme: true },
    // The latest release post. Raw HTML, which the link check does not see: keep the baseUrl in it.
    announcementBar: {
      id: "release-1-5",
      content:
        'anonyma 1.5: presets that add up, batches on every core, and a Rust engine for Node.js. <a href="/anonyma/blog/anonyma-1-5">What changed, and why</a>',
      // The site's primary colour, legible in both colour modes.
      backgroundColor: "#2f6f4e",
      textColor: "#ffffff",
      isCloseable: true,
    },
    navbar: {
      title: "anonyma",
      logo: { alt: "anonyma", src: "img/logo.svg" },
      items: [
        { type: "docSidebar", sidebarId: "docs", position: "left", label: "Docs" },
        { to: "/playground", label: "Playground", position: "left" },
        { to: "/benchmarks", label: "Benchmarks", position: "left" },
        { to: "/blog", label: "Blog", position: "left" },
        { to: "/docs/project/changelog", label: "Changelog", position: "right" },
        { href: "https://www.npmjs.com/package/anonyma", label: "npm", position: "right" },
        { href: repository, label: "GitHub", position: "right" },
      ],
    },
    footer: {
      style: "dark",
      links: [
        {
          title: "Learn",
          items: [
            { label: "Introduction", to: "/docs" },
            { label: "Quick start", to: "/docs/guide/quick-start" },
            { label: "Recipes", to: "/docs/guides/scrub-files" },
            { label: "API reference", to: "/docs/reference/api" },
          ],
        },
        {
          title: "Try",
          items: [
            { label: "Playground", to: "/playground" },
            { label: "Benchmarks", to: "/benchmarks" },
            { label: "Command line", to: "/docs/packages/cli" },
            { label: "Other languages", to: "/docs/guides/other-languages" },
          ],
        },
        {
          title: "Project",
          items: [
            { label: "Releases", to: "/docs/project/releases" },
            { label: "Changelog", to: "/docs/project/changelog" },
            { label: "History and decisions", to: "/docs/project/history" },
            { label: "Security", to: "/docs/project/security" },
            { label: "GitHub", href: repository },
            { label: "npm", href: "https://www.npmjs.com/package/anonyma" },
          ],
        },
      ],
      copyright: `MIT licensed. The playground runs the library in your browser and sends nothing you type to a server.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ["bash", "json"],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
