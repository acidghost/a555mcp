package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/log"
	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/mcp"
	ollama "github.com/ollama/ollama/api"
	"github.com/spf13/cobra"
)

var (
	// Version information filled at build time
	buildVersion = "SNAPSHOT"
	buildCommit  = "unknown"
	buildDate    = "1970-01-01"

	rootCmd = &cobra.Command{
		Use:   "a555mcp",
		Short: "A 555 MCP Host",
		RunE: func(cmd *cobra.Command, args []string) error {
			if *&fRootVersion {
				fmt.Printf("%s version %s (%s) built at %s\n",
					os.Args[0], buildVersion, buildCommit, buildDate)
				return nil
			}

			if fRootConfig == "" {
				return fmt.Errorf("configuration file is required")
			}

			logFile, err := tea.LogToFile("/tmp/a555mcp.log", "a555mcp")
			if err != nil {
				log.Error("Failed to log to file", "err", err)
			} else {
				defer logFile.Close()
			}
			log.Info("Logging to file", "path", logFile.Name())

			log.SetLevel(log.DebugLevel)
			log.SetReportCaller(true)
			log.SetOutput(logFile)
			// XXX: has to come after SetOutput
			log.SetColorProfile(lipgloss.ColorProfile())

			m, err := NewModel()
			if err != nil {
				return err
			}

			log.Info("Starting TUI...")
			p := tea.NewProgram(m, tea.WithAltScreen())
			_, err = p.Run()
			return err
		},
	}

	fRootVersion bool
	fRootConfig  string

	styGray = lipgloss.NewStyle().Foreground(lipgloss.Color("#555"))
)

const (
	layGap           = "\n\n"
	notificationRole = "notification"
	userRole         = "user"
	assistantRole    = "assistant"
	toolRole         = "tool"
)

func init() {
	rootCmd.PersistentFlags().
		BoolVarP(&fRootVersion, "version", "v", false, "Print version information and exit")
	rootCmd.PersistentFlags().
		StringVarP(&fRootConfig, "config", "c", "", "Path to the configuration file")
}

type model struct {
	config struct {
		Servers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"servers"`
		Ollama string `json:"ollama"`
	}

	clients map[string]client.MCPClient
	ollama  *ollama.Client

	w, h      int
	isLoading bool
	tools     []ollama.Tool
	messages  []ollama.Message

	mdr *glamour.TermRenderer

	spinner  spinner.Model
	input    textarea.Model
	viewport viewport.Model
	help     help.Model

	keys struct {
		Quit  key.Binding
		Enter key.Binding
	}
}

// Ollama types extracted from embedded API structs.
type (
	OllamaToolFunctionParameters = struct {
		Type       string                                      `json:"type"`
		Defs       any                                         `json:"$defs,omitempty"`
		Items      any                                         `json:"items,omitempty"`
		Required   []string                                    `json:"required"`
		Properties map[string]OllamaToolFunctionSchemaProperty `json:"properties"`
	}
	OllamaToolFunctionSchemaProperty = struct {
		Type        ollama.PropertyType `json:"type"`
		Items       any                 `json:"items,omitempty"`
		Description string              `json:"description"`
		Enum        []any               `json:"enum,omitempty"`
	}
)

func NewModel() (model, error) {
	var (
		m   model
		err error
	)

	if m.mdr, err = glamour.NewTermRenderer(
		glamour.WithStandardStyle("dracula"),
		glamour.WithEmoji(),
	); err != nil {
		return m, fmt.Errorf("failed to create markdown renderer: %w", err)
	}

	m.spinner = spinner.New()
	m.spinner.Spinner = spinner.Spinner{
		Frames: []string{"☝️", "✌️", "🤟", "🤘", "🤙", "👍"},
		FPS:    time.Second / 2,
	}

	m.input = textarea.New()
	m.input.Placeholder = "Type your message here..."
	m.input.CharLimit = 1000
	m.input.ShowLineNumbers = false
	m.input.Prompt = ""
	m.input.KeyMap.InsertNewline.SetEnabled(false)
	m.input.SetWidth(50)
	// NOTE: the height of the spinner view should be withing the input height
	m.input.SetHeight(10)
	m.input.Focus()

	m.viewport = viewport.New(0, 0)
	m.viewport.KeyMap.Down = key.NewBinding(
		key.WithKeys("shift+down"),
		key.WithHelp("⇧+↓", "scroll down"),
	)
	m.viewport.KeyMap.Up = key.NewBinding(
		key.WithKeys("shift+up"),
		key.WithHelp("⇧+↑", "scroll up"),
	)

	m.help = help.New()

	m.keys.Quit = key.NewBinding(
		key.WithKeys("esc", "ctrl+c"),
		key.WithHelp("⎋/⌃c", "quit"),
	)
	m.keys.Enter = key.NewBinding(
		key.WithKeys("enter"),
		key.WithHelp("⏎", "send message"),
	)

	file, err := os.ReadFile(fRootConfig)
	if err != nil {
		return m, fmt.Errorf("failed to read config file %q: %w", fRootConfig, err)
	}
	if err := json.Unmarshal(file, &m.config); err != nil {
		return m, fmt.Errorf("failed to parse config file %q: %w", fRootConfig, err)
	}

	if m.config.Ollama == "" {
		return m, fmt.Errorf("ollama URL is not configured in %q", fRootConfig)
	}
	ollamaURL, err := url.Parse(m.config.Ollama)
	if err != nil {
		return m, fmt.Errorf("invalid ollama URL %q: %w", m.config.Ollama, err)
	}
	log.Debug("New Ollama client", "url", ollamaURL)
	http.DefaultClient.Transport = LoggingHttpTransport{http.DefaultTransport}
	m.ollama = ollama.NewClient(ollamaURL, http.DefaultClient)

	m.clients = make(map[string]client.MCPClient)
	for name, server := range m.config.Servers {
		c, err := client.NewStdioMCPClient(server.Command, nil, server.Args...)
		if err != nil {
			return m, fmt.Errorf("failed to create client for server %q: %w", name, err)
		}

		log := log.With("server", name)

		initRequest := mcp.InitializeRequest{}
		initRequest.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
		initRequest.Params.ClientInfo = mcp.Implementation{
			Name:    "a555mcp",
			Version: "1.0.0",
		}
		initRequest.Params.Capabilities = mcp.ClientCapabilities{}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		log.Debug("Initializing MCP client", "server", name)
		_, err = c.Initialize(ctx, initRequest)
		if err != nil {
			c.Close()
			for _, c := range m.clients {
				c.Close()
			}
			return m, fmt.Errorf("failed to initialize MCP client for %s: %w", name, err)
		}
		m.clients[name] = c

		resources, err := c.ListResources(ctx, mcp.ListResourcesRequest{})
		if err == nil {
			log.Debug("Gathering resources")
			for _, res := range resources.Resources {
				log.Info(
					"New resource",
					"resource", res.Name,
					"desc", ellipsis(res.Description, 40),
				)
			}
		} else {
			log.Error("Listing resources", "err", err)
		}

		tools, err := c.ListTools(ctx, mcp.ListToolsRequest{})
		if err == nil {
			log.Debug("Gathering tools")
			for _, tool := range tools.Tools {
				log.Info(
					"New tool",
					"tool", tool.Name,
					"desc", ellipsis(tool.Description, 40),
				)
				m.tools = append(m.tools, mcpToolToOllama(name, tool))
			}
		} else {
			log.Error("Listing tools", "err", err)
		}
	}

	return m, nil
}

// LoggingHttpTransport is a custom HTTP transport that logs requests and responses.
type LoggingHttpTransport struct {
	http.RoundTripper
}

func (t LoggingHttpTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqBody := ""
	if req.Body != nil {
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			log.Error("Failed to read request body", "err", err)
			return nil, err
		}
		req.Body.Close()                                    // close the original body
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes)) // restore the body
		reqBody = string(bodyBytes)
	}
	log.Debug("HTTP Request", "method", req.Method, "url", req.URL.String(), "body", reqBody)
	resp, err := t.RoundTripper.RoundTrip(req)
	if err != nil {
		log.Error("HTTP Request failed", "err", err)
		return nil, err
	}
	respBody := ""
	if resp.Body != nil {
		respBodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Error("Failed to read response body", "err", err)
			return nil, err
		}
		resp.Body.Close()                                        // close the original body
		resp.Body = io.NopCloser(bytes.NewBuffer(respBodyBytes)) // restore the body
		respBody = string(respBodyBytes)
	}
	log.Debug("HTTP Response", "status", resp.Status, "body", respBody)
	return resp, nil
}

func mcpToolToOllama(serverName string, tool mcp.Tool) ollama.Tool {
	namespacedName := fmt.Sprintf("%s/%s", serverName, tool.Name)
	return ollama.Tool{
		Type: "function",
		Function: ollama.ToolFunction{
			Name:        namespacedName,
			Description: tool.Description,
			Parameters: OllamaToolFunctionParameters{
				Type:       tool.InputSchema.Type,
				Required:   tool.InputSchema.Required,
				Properties: mcpToolSchemaPropertiesToOllama(tool.InputSchema.Properties),
			},
		},
	}
}

func mcpToolSchemaPropertiesToOllama(props map[string]any) map[string]OllamaToolFunctionSchemaProperty {
	result := make(map[string]OllamaToolFunctionSchemaProperty, len(props))
	for k, v := range props {
		if propMap, ok := v.(map[string]any); ok {
			prop := OllamaToolFunctionSchemaProperty{}
			switch v := propMap["type"].(type) {
			case string:
				prop.Type = []string{v}
			case []string:
				prop.Type = v
			}
			if desc, ok := propMap["description"].(string); ok {
				prop.Description = desc
			}
			if enumRaw, ok := propMap["enum"].([]any); ok {
				for _, e := range enumRaw {
					if str, ok := e.(string); ok {
						prop.Enum = append(prop.Enum, str)
					}
				}
			}
			result[k] = prop
		}
	}
	return result
}

func (m model) Init() tea.Cmd {
	return tea.Batch(textarea.Blink, m.spinner.Tick)
}

func (m model) ShortHelp() []key.Binding {
	return []key.Binding{
		m.keys.Enter,
		m.viewport.KeyMap.Up,
		m.viewport.KeyMap.Down,
		m.keys.Quit,
	}
}

func (m model) FullHelp() [][]key.Binding {
	// TODO: implement full help
	return [][]key.Binding{
		m.ShortHelp(),
	}
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		m.input.SetWidth(min(m.w-10, 50))
		m.help.Width = m.w / 2
		m.viewport.Width = m.w
		// NOTE: use only the input's height since the spinner view is always shorter
		m.viewport.Height = m.h - lipgloss.Height(layGap) -
			m.input.Height() - lipgloss.Height(m.help.View(m))
		m.recomputeViewport()

	case tea.KeyMsg:
		switch {
		case key.Matches(msg, m.keys.Quit):
			for n, c := range m.clients {
				if err := c.Close(); err != nil {
					log.Error("Failed to close MCP client", "server", n, "err", err)
				}
			}
			return m, tea.Quit
		case key.Matches(msg, m.keys.Enter):
			if !m.isLoading && m.input.Value() != "" {
				m.input.Blur()
				m.isLoading = true
				m.keys.Enter.SetEnabled(false)
				m.messages = append(m.messages, ollama.Message{
					Content: m.input.Value(),
					Role:    userRole,
				})
				m.recomputeViewport()
				m.input.Reset()
				return m, m.chat()
			}
		}

	case spinner.TickMsg:
		var spinnerCmd tea.Cmd
		m.spinner, spinnerCmd = m.spinner.Update(msg)
		return m, spinnerCmd

	case ollama.Message:
		log.Debug("LLM", "msg", fmt.Sprintf("%#v", msg))
		replacer := strings.NewReplacer("<think>", "## Thinking", "</think>", "## Reply")
		msg.Content = replacer.Replace(msg.Content)
		m.messages = append(m.messages, msg)
		m.recomputeViewport()
		if msg.Role == assistantRole && len(msg.ToolCalls) > 0 {
			// TODO: ask for confirmation of tool calls
			return m, m.toolCalls(msg.ToolCalls)
		} else {
			m.isLoading = false
			m.keys.Enter.SetEnabled(true)
			m.input.Focus()
		}

	case []mcp.CallToolResult:
		for _, toolRes := range msg {
			log.Debug("Tool call result", "result", toolRes)
			// TODO: tool call result errors
			content := make([]string, 0, len(toolRes.Content))
			for _, c := range toolRes.Content {
				switch v := c.(type) {
				case mcp.TextContent:
					content = append(content, v.Text)
				case mcp.ImageContent, mcp.AudioContent, mcp.EmbeddedResource:
					log.Debug("Ignoring non-text content in tool call result", "content", c)
				}
			}
			m.messages = append(m.messages, ollama.Message{
				Role:    toolRole,
				Content: strings.Join(content, "\n"),
			})
		}
		m.recomputeViewport()
		// send back to LLM
		return m, m.chat()
	}

	var inputCmd tea.Cmd
	m.input, inputCmd = m.input.Update(msg)

	var viewportCmd tea.Cmd
	m.viewport, viewportCmd = m.viewport.Update(msg)

	return m, tea.Batch(inputCmd, viewportCmd)
}

func (m *model) recomputeViewport() {
	m.viewport.SetContent(m.messagesView())
	m.viewport.GotoBottom()
}

func (m *model) chat() tea.Cmd {
	messages := make([]ollama.Message, 0, len(m.messages))
	for _, msg := range m.messages {
		if msg.Role == notificationRole {
			continue
		}
		messages = append(messages, msg)
	}
	client := m.ollama
	tools := m.tools
	return func() tea.Msg {
		var msg ollama.Message
		stream := false
		err := client.Chat(context.Background(), &ollama.ChatRequest{
			Model:    "qwen3:1.7b",
			Stream:   &stream,
			Messages: messages,
			Tools:    tools,
		}, func(resp ollama.ChatResponse) error {
			msg = resp.Message
			return nil
		})
		if err != nil {
			msg = ollama.Message{
				Content: fmt.Sprintf("Error: %v", err),
				Role:    notificationRole,
			}
		}
		return msg
	}
}

func (m *model) toolCalls(toolCalls []ollama.ToolCall) tea.Cmd {
	return func() tea.Msg {
		toolResults := make([]mcp.CallToolResult, 0, len(toolCalls))
		for _, toolCall := range toolCalls {
			serverName, toolName, ok := strings.Cut(toolCall.Function.Name, "/")
			if !ok {
				log.Error("Invalid tool call function name", "name", toolCall.Function.Name)
				continue
			}
			log := log.With("server", serverName, "tool", toolName)
			log.Debug("Tool call", "args", toolCall.Function.Arguments)
			c, ok := m.clients[serverName]
			if !ok {
				log.Error("No client", "server", serverName)
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			toolReq := mcp.CallToolRequest{}
			toolReq.Params.Name = toolName
			toolReq.Params.Arguments = toolCall.Function.Arguments
			toolRes, err := c.CallTool(ctx, toolReq)
			if err != nil {
				log.Error("Failed to call tool", "err", err)
				return nil
			}
			toolResults = append(toolResults, *toolRes)
		}
		return toolResults
	}
}

func (m model) View() string {
	var v string
	v += lipgloss.JoinHorizontal(.2, lipgloss.PlaceHorizontal(20, lipgloss.Center, "a555mcp"), m.help.View(m)) + layGap
	v += m.viewport.View()
	v += layGap
	if m.isLoading {
		// NOTE: keep height below input's height
		v += layGap + lipgloss.PlaceHorizontal(m.w, lipgloss.Center, m.spinner.View()) + layGap
	} else {
		v += lipgloss.PlaceHorizontal(m.w, lipgloss.Center, m.input.View())
	}
	return v
}

func (m model) messagesView() string {
	messagesStrs := make([]string, 0, len(m.messages))
	for _, msg := range m.messages {
		styBox := lipgloss.NewStyle().
			Border(lipgloss.NormalBorder(), true, false, true, false).
			MarginTop(1).
			Width(80)
		var boxPlacement lipgloss.Position
		content := msg.Content
		switch msg.Role {
		case userRole:
			boxPlacement = lipgloss.Right
			styBox = styBox.Align(boxPlacement).MarginRight(2)
			content = m.maybeMarkdown(content)
		case assistantRole:
			boxPlacement = lipgloss.Left
			styBox = styBox.Align(boxPlacement).MarginLeft(2)
			if content != "" {
				content = m.maybeMarkdown(content)
			}
			if len(msg.ToolCalls) > 0 {
				if content != "" {
					content += "\n\n"
				}
				content += styGray.Render("Tool calls:") + "\n"
				toolCallsStrs := make([]string, 0, len(msg.ToolCalls))
				for _, toolCall := range msg.ToolCalls {
					args := make([]string, 0, len(toolCall.Function.Arguments))
					for k, v := range toolCall.Function.Arguments {
						switch v := v.(type) {
						case string:
							args = append(args, fmt.Sprintf("%s:%q", k, v))
						default:
							args = append(args, fmt.Sprintf("%s:%s", k, v))
						}
					}
					toolCallsStrs = append(toolCallsStrs, fmt.Sprintf(
						"%d. %s(%s)",
						toolCall.Function.Index,
						toolCall.Function.Name,
						strings.Join(args, ", "),
					))
				}
				content += strings.Join(toolCallsStrs, "\n")
			}
		case notificationRole, toolRole:
			boxPlacement = lipgloss.Center
			styBox = styBox.Align(lipgloss.Left)
		}
		box := styBox.Render(content)
		messagesStrs = append(messagesStrs, lipgloss.PlaceHorizontal(m.w, boxPlacement, box))
	}
	return strings.Join(messagesStrs, "\n")
}

func (m model) maybeMarkdown(s string) string {
	md, err := m.mdr.Render(s)
	if err != nil {
		log.Warn("Failed to render markdown", "err", err, "content", s)
		return s
	}
	return md
}

func ellipsis(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Errorf("%v", err)
		os.Exit(1)
	}
}
