package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/aws/aws-lambda-go/events"
)

// maxResponseBytes keeps a response, once base64 encoded, under Lambda's
// 6 MB limit for synchronous responses.
const maxResponseBytes = 4 << 20

// handler serves API Gateway HTTP API (payload format 2.0) and Lambda
// function URL requests, which share one event format, with the control
// plane's HTTP handler.
type handler struct {
	next   http.Handler
	logger *slog.Logger
}

func (h *handler) invoke(ctx context.Context, e events.APIGatewayV2HTTPRequest) (events.APIGatewayV2HTTPResponse, error) {
	if e.RequestContext.HTTP.Method == "" {
		return events.APIGatewayV2HTTPResponse{}, errors.New("unsupported event: expected an API Gateway HTTP API (payload format 2.0) or function URL request")
	}
	req, err := toRequest(ctx, e)
	if err != nil {
		h.logger.WarnContext(ctx, "invalid request event", "error", err)
		return plain(http.StatusBadRequest, `{"error":"invalid request"}`), nil
	}
	w := &responseWriter{header: http.Header{}}
	h.next.ServeHTTP(w, req)
	if w.body.Len() > maxResponseBytes {
		h.logger.ErrorContext(ctx, "response too large for lambda", "path", req.URL.Path, "bytes", w.body.Len())
		return plain(http.StatusBadGateway, `{"error":"response too large"}`), nil
	}
	return w.event(), nil
}

// toRequest converts an event to the request it carries.
func toRequest(ctx context.Context, e events.APIGatewayV2HTTPRequest) (*http.Request, error) {
	body := []byte(e.Body)
	if e.IsBase64Encoded {
		decoded, err := base64.StdEncoding.DecodeString(e.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to decode the base64 body: %w", err)
		}
		body = decoded
	}
	target := e.RawPath
	if target == "" {
		target = "/"
	}
	if !strings.HasPrefix(target, "/") {
		return nil, fmt.Errorf("path %q is not absolute", target)
	}
	if e.RawQueryString != "" {
		target += "?" + e.RawQueryString
	}
	req, err := http.NewRequestWithContext(ctx, e.RequestContext.HTTP.Method, target, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.RequestURI = target
	req.ContentLength = int64(len(body))
	// API Gateway lowercases header names and joins repeated headers with
	// commas; cookies come apart from the headers
	for name, value := range e.Headers {
		req.Header.Set(name, value)
	}
	if len(e.Cookies) > 0 {
		req.Header.Set("Cookie", strings.Join(e.Cookies, "; "))
	}
	req.Host = req.Header.Get("Host")
	if req.Host == "" {
		req.Host = e.RequestContext.DomainName
	}
	if ip := e.RequestContext.HTTP.SourceIP; ip != "" {
		req.RemoteAddr = net.JoinHostPort(ip, "0")
	}
	return req, nil
}

// responseWriter buffers a response for the Lambda event.
type responseWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func (w *responseWriter) Header() http.Header { return w.header }

func (w *responseWriter) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

func (w *responseWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(b)
}

// event returns the response as a Lambda event. The body is always base64
// encoded, so binary assets pass through unchanged; Set-Cookie headers go in
// the cookies field, since the headers field holds one value per name.
func (w *responseWriter) event() events.APIGatewayV2HTTPResponse {
	status := w.status
	if status == 0 {
		status = http.StatusOK
	}
	// as net/http does, a body without a declared type is sniffed
	if w.body.Len() > 0 && w.header.Get("Content-Type") == "" {
		w.header.Set("Content-Type", http.DetectContentType(w.body.Bytes()))
	}
	resp := events.APIGatewayV2HTTPResponse{
		StatusCode:      status,
		Headers:         map[string]string{},
		Body:            base64.StdEncoding.EncodeToString(w.body.Bytes()),
		IsBase64Encoded: true,
	}
	for name, values := range w.header {
		if name == "Set-Cookie" {
			resp.Cookies = append(resp.Cookies, values...)
			continue
		}
		resp.Headers[name] = strings.Join(values, ", ")
	}
	return resp
}

func plain(status int, body string) events.APIGatewayV2HTTPResponse {
	return events.APIGatewayV2HTTPResponse{
		StatusCode: status,
		Headers:    map[string]string{"Content-Type": "application/json"},
		Body:       body,
	}
}
