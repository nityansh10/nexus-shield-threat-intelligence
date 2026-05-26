import React from 'react';
import NexusShieldConsole from '../index.js';

const globalStyles = `
  *, *::before, *::after {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
  }

  html, body, #root {
    height: 100%;
    width: 100%;
  }

  body {
    background: #050811;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    overflow-x: hidden;
  }

  ::-webkit-scrollbar {
    width: 6px;
    height: 6px;
  }

  ::-webkit-scrollbar-track {
    background: #0b1220;
  }

  ::-webkit-scrollbar-thumb {
    background: #1c2e4a;
    border-radius: 3px;
  }

  ::-webkit-scrollbar-thumb:hover {
    background: #00f0ff40;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; box-shadow: 0 0 6px rgba(0, 240, 255, 0.8); }
    50%       { opacity: 0.4; box-shadow: 0 0 2px rgba(0, 240, 255, 0.2); }
  }

  @keyframes scanline {
    0%   { transform: translateY(-100%); }
    100% { transform: translateY(100vh); }
  }
`;

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  render() {
    if (this.state.error) {
      return (
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          minHeight: '100vh',
          background: '#050811',
          color: '#ff0055',
          fontFamily: '"Courier New", Courier, monospace',
          padding: '40px',
          textAlign: 'center',
        }}>
          <h1 style={{ fontSize: '20px', marginBottom: '16px', letterSpacing: '2px' }}>
            // SYSTEM FAULT — PIPELINE EXECUTION HALTED
          </h1>
          <pre style={{
            fontSize: '12px',
            color: '#a0b3cf',
            background: '#0b1220',
            padding: '20px',
            borderRadius: '4px',
            border: '1px solid #1c2e4a',
            maxWidth: '600px',
            overflowX: 'auto',
          }}>
            {this.state.error.toString()}
          </pre>
          <button
            onClick={() => this.setState({ error: null })}
            style={{
              marginTop: '24px',
              padding: '10px 24px',
              background: '#00f0ff',
              color: '#050811',
              border: 'none',
              borderRadius: '4px',
              fontFamily: '"Courier New", Courier, monospace',
              fontWeight: 'bold',
              fontSize: '13px',
              cursor: 'pointer',
              letterSpacing: '1px',
            }}
          >
            REINITIALIZE SYSTEM
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

export default function App() {
  return (
    <>
      <style>{globalStyles}</style>
      <ErrorBoundary>
        <NexusShieldConsole />
      </ErrorBoundary>
    </>
  );
}
