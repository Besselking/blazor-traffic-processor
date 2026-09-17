# BlazorTrafficProcessor (BTP)
A BurpSuite extension to aid pentesting web applications that use Blazor Server/BlazorPack. Primary functionality includes converting BlazorPack messages to JSON and vice versa, introduces tamperability for BlazorPack serialized messages.

## Build

### Prerequisites
- Install [Java 18](https://www.oracle.com/java/technologies/javase/jdk18-archive-downloads.html) on your building machine.
- Install [Gradle](https://gradle.org/install/) on your building machine.
- Ensure the `JAVA_HOME` environment variable is set to the JDK 18 path if you have multiple versions of Java installed.
    - _NOTE: This project requires Java 17+._

### Build Steps
1. Clone the repository with `git clone https://github.com/AonCyberLabs/BlazorTrafficProcessor`
2. `cd BlazorTrafficProcessor`
3. `gradle build`
4. The built JAR file will be located at `BlazorTrafficProcessor/build/libs/BlazorTrafficProcessor-1.0.jar`

## Usage

### Installing the extension in Burp 
* Download the latest `.jar` from the Releases page or build the project manually.
  * _The project has been submitted to the BApp store and is pending review_.
* Load the extension into Burp
  1. Click "Extender"
  2. Under "Extensions", click "Add"
  3. In the file selector, choose the downloaded/built `.jar` file

**NOTE: when using the legacy LongPolling downgrade, it is recommended to check "Other Binary" in your Burp History filter, this will allow you to see data returned by the application.**

### Using the Extension
BTP works against both transports Blazor Server can use:

* **WebSockets (default).** Blazor's preferred transport is left alone, and BTP reads the BlazorPack frames directly off the proxied WebSocket.
  * BlazorPack frames are highlighted as Cyan in the "WebSockets history" tab.
  * The "BTP" tab appears on each in-scope WebSocket message that contains BlazorPack data, in the WebSockets history and in Intercept.
  * Editing the JSON in that tab re-serializes it back to BlazorPack when the frame is forwarded.
* **LongPolling over HTTP (legacy, opt-in).** Enable the "Force LongPolling downgrade (WebSockets -> HTTP)" checkbox in the BTP suite tab to have BTP rewrite the Blazor negotiate response, as older versions of the extension always did. See [Downgrade Explained](#downgrade-explained-ws---http-legacy) below.

Common to both:
* All BlazorPack-enabled requests or responses will be highlighted as Cyan within the "Http History" tab in Burpsuite.
* The "BTP" request/response editor tab, which appears on each in-scope request or response that contains BlazorPack messages. 
  * Clicking on this tab will convert the serialized data from BlazorPack to JSON.
  * After editing the JSON (either in Intercept or Repeater), click the "Raw" tab to re-serialize with your payloads
* Page deltas (`JS.RenderBatch`) are decoded automatically. See [Render Batches](#render-batches-page-deltas) below.
* Messages that arrive split across several WebSocket messages are reassembled. See [Split Messages](#split-messages) below.
* The "BTP" Burpsuite tab, which allows for ad-hoc conversions of Blazor->JSON and JSON->Blazor
  * The left-hand editor is for your input (JSON or raw Blazor)
  * The right-hand editor is for the results of the conversion
  * A drop-down menu on the bottom of the window lets you select "Blazor->JSON" or "JSON->Blazor"
  * The Serialize/Deserialize button at the top is how you trigger the conversion
* Right-click menu option called "Send body to BTP tab"
  * You can right-click any request, response, or WebSocket message and select "Extensions" -> "BlazorTrafficProcessor" -> "Send body to BTP tab"
  * This sends the selected request/response body or WebSocket frame payload to the BTP tab, so you don't have to worry about copying/pasting raw bytes
* The "BTP Repeater" tab, for capturing a client-to-server invocation, editing it, and sending it back. See [Repeater](#repeater) below.

## Repeater
Blazor Server keeps UI state on the server, keyed by ids the browser sends back in its invocations - `eventHandlerId`,
`componentId`, and the arguments to `DispatchEventAsync` / `BeginInvokeDotNetFromJS`. Those ids are exactly the kind
of thing worth tampering with: firing a handler the UI never exposed to you, acting on another component, or pushing a
malformed argument into a server-side handler. This is an authenticated user manipulating their own outbound traffic -
no MITM needed, since it is the tester's own connection.

The "BTP Repeater" suite tab makes that loop quick:

1. Right-click a client-to-server WebSocket message (in the WebSockets history or an intercepted message) and choose
   **"Send invocation to BTP Repeater (edit & resend)"**. BTP deserializes it to JSON - reassembling it from the
   WebSockets history first if it arrived split - and loads it into the Repeater, selecting the connection it came from.
2. Edit the JSON.
3. Click **"Serialize & Send"**. BTP re-serializes the edited JSON to BlazorPack and sends it back through the live
   connection.

A message sent this way does **not** appear in Burp's WebSockets history - Burp does not record messages an extension
injects, the same way it does not record `http().sendRequest()` traffic. The Repeater therefore keeps its own **Sent**
record below the editor (with a timestamp, direction, connection and byte count for each send), and logs a hex preview
to the extension's Output tab. A server *response* to the injected message does travel back through the proxy, so that
part shows in the history as usual.

Notes:
* The **Connection** dropdown lists the Blazor WebSockets currently open through the proxy; **Refresh** re-reads it.
  A connection that has closed drops off the list, and sending on one that closes is reported rather than silently lost.
* **Send as** defaults to "To server", the useful direction for invocation tampering; "To client" is available for
  testing how the browser handles server-originated messages.
* A split message is sent as a single frame. The server reconstructs a message from its VarInt length prefix, not from
  the WebSocket framing, so the original fragmentation does not need reproducing - which is why an invocation that is
  read-only in the editor tab (because one frame cannot represent the whole message) is fully editable here.

## Render Batches (Page Deltas)
Blazor Server pushes UI updates to the browser as `JS.RenderBatch` invocations. The batch itself is **not** BlazorPack:
it is a separate custom binary format produced by [`RenderBatchWriter`](https://github.com/dotnet/aspnetcore/blob/main/src/Components/Shared/src/RenderBatchWriter.cs)
and read by `blazor.server.js`. BTP used to surface it as an opaque wall of hex.

BTP now decodes it, adding a `RenderBatch` object next to the raw bytes:

```json
[{
  "Target": "JS.RenderBatch",
  "MessageType": 1,
  "Headers": 0,
  "Arguments": [3, {
    "BinaryHeader": 4767,
    "BinaryBytes": "0500000001000000...",
    "RenderBatch": {
      "UpdatedComponents": [
        {"ComponentId": 5, "Edits": [{"Type": "PrependFrame", "SiblingIndex": 0, "ReferenceFrameIndex": 0}]}
      ],
      "ReferenceFrames": [
        {"Index": 0, "FrameType": "Element", "SubtreeLength": 9, "ElementName": "div"},
        {"Index": 1, "FrameType": "Attribute", "AttributeName": "class", "AttributeValue": "container", "AttributeEventHandlerId": 0},
        {"Index": 2, "FrameType": "Text", "TextContent": "Even geduld, de applicatie wordt geladen..."}
      ],
      "DisposedComponentIds": [],
      "DisposedEventHandlerIds": []
    }
  }]
}]
```

* `UpdatedComponents` are the diffs: per component, the list of edits to apply. `ReferenceFrameIndex` points into
  `ReferenceFrames`, which is why each frame is tagged with its `Index`.
* `PermutationListEntry` edits report `MoveToSiblingIndex` instead of `ReferenceFrameIndex`, because those two share
  a slot in the wire format.
* `AttributeEventHandlerId` is the handler id you can reuse in a `DispatchEventAsync` invocation.
* Frame types the client never receives (`ComponentReferenceCapture`, `ComponentRenderMode`, `NamedEvent`) are written
  as padding, so they appear with a frame type and nothing else. They still occupy an index.

**`RenderBatch` is a decoded view, not an editable one.** `BinaryBytes` stays authoritative: re-serialization reads
`BinaryHeader`/`BinaryBytes` and ignores `RenderBatch`, so a message round-trips byte-for-byte. To tamper with a batch,
edit `BinaryBytes`.

If a batch cannot be decoded (a truncated capture, or a future format change) the `RenderBatch` key is simply omitted
and a note is written to the extension's output log; the raw bytes are always left intact. Note that the decoder reads
the UTF-8 string table, which is what Blazor Server emits; the newer opt-in UTF-16 string table is not decoded.

## Split Messages
A BlazorPack message is not guaranteed to arrive in a single WebSocket message. Large payloads - render batches
especially - are commonly split, which is exactly why every message carries a VarInt length prefix. Taken on its own,
such a message is undecodable: the first piece declares a length longer than the bytes present, and the later pieces
start mid-message.

A BlazorPack message and a WebSocket message come apart in both directions. A message can be split across several
WebSocket messages, and Burp can hand the extension a whole message while the WebSockets history still lists the
pieces it arrived in - in which case only the first row is annotated and the rest look like unrelated traffic.

Worse, Burp does not hand an extension every piece: a large render batch reaches the proxy message handler as its
first piece only, and the rest never arrives there at all. It does all reach the WebSockets history, which is what
you see listed, so that is where such a message has to be put back together.

BTP handles all of this. It treats each direction of each connection as a byte stream, buffers it, and deserializes
messages as their last byte arrives; every deserialized message is indexed so that a row showing any part of it
resolves to the whole thing; and when the live stream never saw the rest, the message is rebuilt by replaying that
connection and direction from the WebSockets history. Clicking any of the WebSocket messages that carried a message
shows all of it:

```json
{
   "_BTP": "Read-only: this BlazorPack message arrived split across 4 websocket messages, so edits here cannot be written back to a single one.",
   "Messages": [{ "Target": "JS.RenderBatch", "...": "..." }]
}
```

The first message in each direction is the SignalR handshake (`{"protocol":"blazorpack","version":1}` followed by a
`0x1E` record separator), which is not a length-prefixed BlazorPack message. BTP consumes it as its own record - read
as a length prefix, its leading `{` would mean "expect 123 more bytes" and throw the rest of the stream out of
alignment.

Worth knowing:
* **Every message on a Blazor WebSocket gets a BTP tab**, including ones BTP cannot deserialize. Rather than hiding
  the tab, it explains what the message is: a handshake record, a piece of a message BTP never saw in full, or bytes
  it could not make sense of. Unlike the HTTP editor tabs, the WebSocket tab does not require the target to be in
  scope - the `_blazor` upgrade URL is specific enough on its own, and requiring scope as well made a missing tab
  impossible to tell apart from a bug.
* **Reassembled views are read-only.** The decoded message spans several WebSocket messages, so there is no single one
  to write edits back to. BTP returns the original bytes untouched and ignores edits made in this view. Messages that
  arrive whole are unaffected and stay editable.
* **Troubleshooting.** The extension logs the build it was made from on load (`[+] BTP v1.0 Extension loaded, build
  <commit>`), so a bug report can name the exact jar. Ticking "Verbose WebSocket logging" in the BTP suite tab adds a
  line per proxied WebSocket message giving its direction, size, how many BlazorPack messages it completed, and how
  many bytes are still buffered awaiting the rest - which is what to look at if stitching is not behaving.
* **Reassembly happens as traffic passes through the proxy.** Messages proxied before the extension was loaded were
  never streamed through it, so they cannot be reassembled after the fact.
* A stream that loses alignment is detected and reset, rather than emitting nonsense or buffering indefinitely.
  Two checks catch it: every BlazorPack message is a MessagePack array, so a body that does not start with an array
  header means the stream is out of step; and a WebSocket cannot interleave the data frames of two messages, so a
  payload that is itself a complete message proves that anything still buffered was never the start of one. Without
  the second check a single bad length prefix swallows every message after it, permanently. Both log a line saying
  what was discarded.

## Downgrade Explained (WS -> HTTP) (legacy)
_This is no longer the default. BTP now handles BlazorPack over WebSockets natively; the downgrade is kept as an opt-in for workflows that rely on the HTTP tooling (Repeater, Intruder, and the request/response editors)._

Blazor server normally communicates via WebSockets, though it supports other protocols such as LongPolling over HTTP.
During the connection initiation between your browser and the server, one of the first requests sent will look like the following:
```http
POST /_blazor/negotiate?negotiateVersion=1 HTTP/1.1
Host: localhost:5003
[...]
X-Requested-With: XMLHttpRequest
X-SignalR-User-Agent: Microsoft SignalR/0.0 (0.0.0-DEV_BUILD; Unknown OS; Browser; Unknown Runtime Version)
[...]
```

The response will contain the available transports as follows:
```http
HTTP/1.1 200 OK
Content-Length: 316
Connection: close
Content-Type: application/json
Date: Thu, 22 Sep 2022 13:30:17 GMT
Server: Kestrel

{"negotiateVersion":1,
  "connectionId":"XXX",
  "connectionToken":"XXX",
  "availableTransports":[
    {"transport":"WebSockets","transferFormats":["Text","Binary"]},
    {"transport":"ServerSentEvents","transferFormats":["Text"]},
    {"transport":"LongPolling","transferFormats":["Text","Binary"]}
  ]
}
```

This negotiation determines how the client and server will establish their connection. WebSockets is the preferred method, but earlier releases of Burp's Montoya API had no way to add a custom tab to a WebSocket message, so BTP forced the connection over HTTP in order to be useful.
With the downgrade enabled, the browser (and JavaScript running in it) that you're proxying traffic through will see that websockets aren't supported and fall back to using HTTP ("LongPolling").
BTP performs this downgrade when the checkbox in the BTP suite tab is ticked, observable via the Original/Modified versions of the Blazor negotiation HTTP response. The setting is remembered across Burp restarts.

The Montoya API now exposes WebSocket creation handlers, full read/modify/drop interception of proxied frames, and extension-provided WebSocket message editors, so the downgrade is no longer needed to read or tamper with BlazorPack. It is left in place because Repeater and Intruder workflows are still richer over HTTP than over WebSockets.

## Example Requests

### Change value of an Input Field
Request Body:
```text
ºÀ·BeginInvokeDotNetFromJS¡2À²DispatchEventAsyncÙ[{"eventHandlerId":4,"eventName":"change","eventFieldInfo":{"componentId":27,"fieldValue":"asdfasdfasdf"}},{"value":"asdfasdfasdf"}]
```

Deserialized:
```json
[
  {
    "Target":"BeginInvokeDotNetFromJS",
    "Headers":0,
    "Arguments":[
      "2","null","DispatchEventAsync",1, [
        {"eventFieldInfo": {"componentId":27,"fieldValue":"asdfasdfasdf"}, 
        "eventHandlerId":4,"eventName":"change"},
        {"value":"asdfasdfasdf"}
      ]
    ],
  "MessageType":1
  }
]
```

### Update the rendered web page
Request body:
```text
À±OnRenderCompletedÀ
```

Deserialized:
```json
[
  {
    "Target":"OnRenderCompleted",
    "Headers":0,
    "Arguments":[5,"null"],
    "MessageType":1
  }
]
```

### End an invocation
Request body (What you'll see in Burp):
```text
+ÀµEndInvokeJSFromDotNetÃ­[3,true,null]
```

Request body bytes (What you'll see in the "Inspector" tab if you highlight the request body)
```text
\x2b\x95\x01\x80\xc0\xb5EndInvokeJSFromDotNet\x93\x03\xc3\xad[3,true,null]
[length][MessageType,Headers,InvocationId,Target,[Arguments]]
[\x2b][MessageType=\x01,Headers=\x80,InvocationId=\xc0,Target=\xb5EndInvokeJSFromDotNet,Arguments=[One=\x03,Two=\xc3,Three=\xad[3,true,null]]]
```

#### Byte Breakdown
_[InvocationMessage Encoding Spec](https://github.com/dotnet/aspnetcore/blob/main/src/SignalR/docs/specs/HubProtocol.md#invocation-message-encoding-1)_

1. `\x2b` - the size byte for this payload, value = 43
   * [CyberChef Formula](https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')VarInt_Decode()&input=MmI)
2. `\x95` - an array header, representing a 5-element array
3. `\x01` - integer w/ value of 1, representing the message type (Invocation)
4. `\x80` - Map of length 0, representing the headers (only seen empty map while testing)
5. `\xc0` - NIL, representing the invocationId is null
6. `\xb5` - Raw string header of length 21, representing the "Target"
7. `EndInvokeJSFromDotNet` - the "Target" raw string
8. `\x93` - an array header, representing a 3-element array for the arguments
9. `\x03` - integer w/ value of 3, first argument to the "Target" function
10. `\xc3` - boolean w/ value of true, second argument to the "Target" function
11. `\xad` - Raw string header of length 13, representing the third argument to the "Target" function
12. `[3,true,null]` - the third argument raw string

Deserialized:
```json
[
  {
    "Target":"EndInvokeJSFromDotNet",
    "Headers":0,
    "Arguments": [
      3,true,
      [3,true,null]
    ],
    "MessageType":1
  }
]
```
Copyright 2023 Aon plc
