/**
 * Renders assistant response text as GitHub-Flavored Markdown.
 *
 * Used for streamed assistant answers (and the post-approval assistant reply).
 * The accumulated response is re-rendered on each update, so partial/incomplete
 * markdown (an unclosed **bold**, a half-written table or fenced block) renders
 * as best it can mid-stream and resolves once more text arrives — react-markdown
 * tolerates incomplete input without throwing, keeping the UI stable.
 *
 * Styling lives in the scoped `markdown.css` (`.md` wrapper class) so it matches
 * the app theme without leaking into the rest of the inline-styled UI. Links are
 * forced to open in a new tab safely (noopener noreferrer).
 */

import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import './markdown.css';

export default function MarkdownMessage({ content }: { content: string }) {
  return (
    <div className="md">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          a: ({ children, ...props }) => (
            <a {...props} target="_blank" rel="noopener noreferrer">
              {children}
            </a>
          ),
        }}
      >
        {content}
      </ReactMarkdown>
    </div>
  );
}
