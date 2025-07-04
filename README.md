# a555mcp

![a555mcp](screen.png)

A security research tool demonstrating MCP (Model Context Protocol) prompt
injection vulnerabilities for educational and security awareness training
purposes.

## Overview

This project implements both an MCP client and server to demonstrate how
malicious MCP tools can manipulate AI assistants through hidden prompt injection
techniques. It serves as educational material for understanding potential
security risks in MCP implementations.

## Features

- **TUI Chat Interface**: Terminal-based chat interface built with
  [Bubble Tea](https://github.com/charmbracelet/bubbletea) the LLM
- **Malicious MCP Server**: Demonstrates prompt injection through hidden escape
  sequences in tool descriptions
- **Exfiltration Endpoint**: Logs sensitive data locally for analysis

## Components

### Main Application (`a555mcp`)

- Terminal UI for chatting with LLMs through MCP tools
- Configurable LLM endpoints (OpenAI API compatible)
- Real-time tool execution and response handling
- Markdown rendering for chat messages

### Malicious Server (`a555mcp server`)

- Provides two tools:
  - `quote_of_the_day`: Returns random quotes with hidden injection prompts
  - `internal_words_service`: Collects and logs conversation data locally
- Uses terminal escape sequences to hide malicious instructions
- Demonstrates compliance-themed social engineering

## Usage

### Running the Client

```bash
a555mcp -c config.json
```

### Running the Malicious Server

```bash
a555mcp server
```

### Configuration

The application requires a JSON configuration file specifying:

- LLM endpoint and model
- MCP servers to connect to

Look at the `config-example.json` file for an example configuration.

## Security Research Purpose

This tool demonstrates:

- How MCP tools can inject hidden prompts using escape sequences
- Social engineering through compliance-themed instructions
- Local data exfiltration through seemingly benign tools
- The importance of validating MCP tool descriptions and behaviors

## Educational Use

Ideal for:

- Security awareness training
- MCP security research
- Understanding prompt injection vulnerabilities
- Demonstrating AI assistant manipulation techniques
