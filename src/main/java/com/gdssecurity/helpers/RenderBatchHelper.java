/**
 * Copyright 2023 Aon plc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.gdssecurity.helpers;

import org.json.JSONArray;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;

/**
 * Class to decode the binary "RenderBatch" (page delta) payload carried by JS.RenderBatch invocations.
 *
 * Blazor Server pushes UI updates to the browser as a custom binary blob, not as BlazorPack/MessagePack.
 * It is produced by RenderBatchWriter and consumed by OutOfProcessRenderBatch in blazor.server.js.
 * See https://github.com/dotnet/aspnetcore/blob/main/src/Components/Shared/src/RenderBatchWriter.cs
 *
 * Layout (all integers little-endian):
 *   [diff and frame data ...][string data ...][string locations ...][5 trailing int32 offsets]
 * The five trailing offsets point at, in order: updated components, reference frames, disposed
 * component ids, disposed event handler ids, and the string table. Each of the first four sections
 * starts with an int32 count. Strings are referenced by index into the string table, where -1 is null.
 */
public final class RenderBatchHelper {

    // The five section offsets written at the very end of the batch
    private static final int TRAILER_LENGTH = 20;
    // Each reference frame occupies a fixed 20 bytes: an int32 frame type plus 16 bytes of type-specific data
    private static final int FRAME_ENTRY_LENGTH = 20;
    // Each edit occupies a fixed 16 bytes: four int32s
    private static final int EDIT_ENTRY_LENGTH = 16;
    private static final int POINTER_LENGTH = 4;
    private static final int NULL_STRING_INDEX = -1;

    private final byte[] batch;
    private final int stringTableOffset;

    private RenderBatchHelper(byte[] batch, int stringTableOffset) {
        this.batch = batch;
        this.stringTableOffset = stringTableOffset;
    }

    /**
     * Decodes a RenderBatch blob into its JSON representation
     * @param batch - the raw render batch bytes, i.e. the second argument of a JS.RenderBatch invocation
     * @return a JSONObject describing the batch, or null if the blob is not a well-formed render batch
     */
    public static JSONObject decode(byte[] batch) {
        if (batch == null || batch.length < TRAILER_LENGTH) {
            return null;
        }
        try {
            int trailer = batch.length - TRAILER_LENGTH;
            int updatedComponentsOffset = readInt32(batch, trailer);
            int referenceFramesOffset = readInt32(batch, trailer + 4);
            int disposedComponentIdsOffset = readInt32(batch, trailer + 8);
            int disposedEventHandlerIdsOffset = readInt32(batch, trailer + 12);
            int stringTableOffset = readInt32(batch, trailer + 16);

            // A truncated or non-RenderBatch blob shows up here as an offset outside the payload
            requireOffset(updatedComponentsOffset, trailer);
            requireOffset(referenceFramesOffset, trailer);
            requireOffset(disposedComponentIdsOffset, trailer);
            requireOffset(disposedEventHandlerIdsOffset, trailer);
            requireOffset(stringTableOffset, trailer);

            RenderBatchHelper reader = new RenderBatchHelper(batch, stringTableOffset);

            JSONObject decoded = new JSONObject();
            decoded.put("UpdatedComponents", reader.readUpdatedComponents(updatedComponentsOffset));
            decoded.put("ReferenceFrames", reader.readReferenceFrames(referenceFramesOffset));
            decoded.put("DisposedComponentIds", reader.readInt32Array(disposedComponentIdsOffset));
            decoded.put("DisposedEventHandlerIds", reader.readInt64Array(disposedEventHandlerIdsOffset));
            return decoded;
        } catch (Exception e) {
            // Any malformed blob lands here, and the caller falls back to the raw hex representation
            return null;
        }
    }

    /**
     * Reads the updated components section: a count, then one pointer per diff
     * @param offset - the offset of the section within the batch
     * @return a JSONArray of diffs, each holding a component id and its edits
     */
    private JSONArray readUpdatedComponents(int offset) {
        int count = readInt32(this.batch, offset);
        requireCount(count, POINTER_LENGTH);
        JSONArray diffs = new JSONArray();
        for (int i = 0; i < count; i++) {
            int diffOffset = readInt32(this.batch, offset + 4 + (i * POINTER_LENGTH));
            requireOffset(diffOffset, this.batch.length - TRAILER_LENGTH);
            JSONObject diff = new JSONObject();
            diff.put("ComponentId", readInt32(this.batch, diffOffset));
            diff.put("Edits", readEdits(diffOffset + 4));
            diffs.put(diff);
        }
        return diffs;
    }

    /**
     * Reads the edits belonging to a single diff: a count, then fixed-width edit entries
     * @param offset - the offset of the edit count within the batch
     * @return a JSONArray of decoded edits
     */
    private JSONArray readEdits(int offset) {
        int count = readInt32(this.batch, offset);
        requireCount(count, EDIT_ENTRY_LENGTH);
        JSONArray edits = new JSONArray();
        for (int i = 0; i < count; i++) {
            int editOffset = offset + 4 + (i * EDIT_ENTRY_LENGTH);
            int type = readInt32(this.batch, editOffset);
            // The third int32 is a shared slot, holding either a reference frame index or a move target
            int sharedSlot = readInt32(this.batch, editOffset + 8);
            String removedAttributeName = readString(readInt32(this.batch, editOffset + 12));

            JSONObject edit = new JSONObject();
            edit.put("Type", editTypeName(type));
            edit.put("SiblingIndex", readInt32(this.batch, editOffset + 4));
            if (type == 9) { // PermutationListEntry is the only edit that reads the slot as a sibling index
                edit.put("MoveToSiblingIndex", sharedSlot);
            } else {
                edit.put("ReferenceFrameIndex", sharedSlot);
            }
            if (removedAttributeName != null) {
                edit.put("RemovedAttributeName", removedAttributeName);
            }
            edits.put(edit);
        }
        return edits;
    }

    /**
     * Reads the reference frames section: a count, then fixed-width frame entries
     * @param offset - the offset of the section within the batch
     * @return a JSONArray of decoded frames, each tagged with its index so edits can be followed
     */
    private JSONArray readReferenceFrames(int offset) {
        int count = readInt32(this.batch, offset);
        requireCount(count, FRAME_ENTRY_LENGTH);
        JSONArray frames = new JSONArray();
        for (int i = 0; i < count; i++) {
            int frameOffset = offset + 4 + (i * FRAME_ENTRY_LENGTH);
            int frameType = readInt32(this.batch, frameOffset);

            JSONObject frame = new JSONObject();
            frame.put("Index", i);
            frame.put("FrameType", frameTypeName(frameType));
            switch (frameType) {
                case 1: // Element
                    frame.put("SubtreeLength", readInt32(this.batch, frameOffset + 4));
                    frame.put("ElementName", jsonSafe(readString(readInt32(this.batch, frameOffset + 8))));
                    break;
                case 2: // Text
                    frame.put("TextContent", jsonSafe(readString(readInt32(this.batch, frameOffset + 4))));
                    break;
                case 3: // Attribute
                    frame.put("AttributeName", jsonSafe(readString(readInt32(this.batch, frameOffset + 4))));
                    frame.put("AttributeValue", jsonSafe(readString(readInt32(this.batch, frameOffset + 8))));
                    frame.put("AttributeEventHandlerId", readInt64(this.batch, frameOffset + 12));
                    break;
                case 4: // Component
                    frame.put("SubtreeLength", readInt32(this.batch, frameOffset + 4));
                    frame.put("ComponentId", readInt32(this.batch, frameOffset + 8));
                    break;
                case 5: // Region
                    frame.put("SubtreeLength", readInt32(this.batch, frameOffset + 4));
                    break;
                case 6: // ElementReferenceCapture
                    frame.put("ElementReferenceCaptureId", jsonSafe(readString(readInt32(this.batch, frameOffset + 4))));
                    break;
                case 8: // Markup
                    frame.put("MarkupContent", jsonSafe(readString(readInt32(this.batch, frameOffset + 4))));
                    break;
                default:
                    // ComponentReferenceCapture, ComponentRenderMode and NamedEvent are written as padding only,
                    // but still occupy a slot so that the edits' reference frame indices stay correct
                    break;
            }
            frames.put(frame);
        }
        return frames;
    }

    /**
     * Reads a section holding a count followed by that many int32 values
     * @param offset - the offset of the section within the batch
     * @return a JSONArray of the values
     */
    private JSONArray readInt32Array(int offset) {
        int count = readInt32(this.batch, offset);
        requireCount(count, 4);
        JSONArray values = new JSONArray();
        for (int i = 0; i < count; i++) {
            values.put(readInt32(this.batch, offset + 4 + (i * 4)));
        }
        return values;
    }

    /**
     * Reads a section holding a count followed by that many int64 values
     * @param offset - the offset of the section within the batch
     * @return a JSONArray of the values
     */
    private JSONArray readInt64Array(int offset) {
        int count = readInt32(this.batch, offset);
        requireCount(count, 8);
        JSONArray values = new JSONArray();
        for (int i = 0; i < count; i++) {
            values.put(readInt64(this.batch, offset + 4 + (i * 8)));
        }
        return values;
    }

    /**
     * Resolves a string table index to its value
     * @param index - the string table index, where -1 encodes null
     * @return the decoded string, or null
     */
    private String readString(int index) {
        if (index == NULL_STRING_INDEX) {
            return null;
        }
        if (index < 0) {
            throw new IllegalArgumentException("Negative string table index: " + index);
        }
        int locationOffset = this.stringTableOffset + (index * POINTER_LENGTH);
        if (locationOffset + 4 > this.batch.length - TRAILER_LENGTH) {
            throw new IllegalArgumentException("String table index out of range: " + index);
        }
        int stringOffset = readInt32(this.batch, locationOffset);
        // .NET's BinaryWriter prefixes strings with a 7-bit encoded (LEB128) UTF-8 byte count
        int lengthBytes = 0;
        int length = 0;
        int shift = 0;
        while (true) {
            if (stringOffset + lengthBytes >= this.batch.length) {
                throw new IllegalArgumentException("String length prefix runs past the end of the batch");
            }
            int b = this.batch[stringOffset + lengthBytes] & 0xFF;
            length |= (b & 0x7F) << shift;
            lengthBytes++;
            if ((b & 0x80) == 0) {
                break;
            }
            shift += 7;
            if (shift > 28) {
                throw new IllegalArgumentException("Malformed string length prefix");
            }
        }
        int start = stringOffset + lengthBytes;
        if (length < 0 || start + length > this.batch.length) {
            throw new IllegalArgumentException("String runs past the end of the batch");
        }
        return new String(this.batch, start, length, StandardCharsets.UTF_8);
    }

    /**
     * Maps a RenderTreeEditType value to its name
     * @param type - the numeric edit type
     * @return the name, or the raw value for anything unrecognised
     */
    private static String editTypeName(int type) {
        switch (type) {
            case 1: return "PrependFrame";
            case 2: return "RemoveFrame";
            case 3: return "SetAttribute";
            case 4: return "RemoveAttribute";
            case 5: return "UpdateText";
            case 6: return "StepIn";
            case 7: return "StepOut";
            case 8: return "UpdateMarkup";
            case 9: return "PermutationListEntry";
            case 10: return "PermutationListEnd";
            default: throw new IllegalArgumentException("Unknown render tree edit type: " + type);
        }
    }

    /**
     * Maps a RenderTreeFrameType value to its name
     * @param type - the numeric frame type
     * @return the name
     */
    private static String frameTypeName(int type) {
        switch (type) {
            case 0: return "None";
            case 1: return "Element";
            case 2: return "Text";
            case 3: return "Attribute";
            case 4: return "Component";
            case 5: return "Region";
            case 6: return "ElementReferenceCapture";
            case 7: return "ComponentReferenceCapture";
            case 8: return "Markup";
            case 9: return "ComponentRenderMode";
            case 10: return "NamedEvent";
            default: throw new IllegalArgumentException("Unknown render tree frame type: " + type);
        }
    }

    /**
     * Converts a possibly-null string into something JSONObject.put accepts
     * @param value - the string to convert
     * @return the string, or JSONObject.NULL
     */
    private static Object jsonSafe(String value) {
        return value == null ? JSONObject.NULL : value;
    }

    /**
     * Validates that a section offset points inside the batch payload
     * @param offset - the offset to check
     * @param limit - the first byte that is not payload
     */
    private static void requireOffset(int offset, int limit) {
        if (offset < 0 || offset >= limit) {
            throw new IllegalArgumentException("Section offset outside the batch: " + offset);
        }
    }

    /**
     * Validates that an entry count could physically fit in the batch
     * @param count - the count to check
     * @param entryLength - the size of a single entry
     */
    private void requireCount(int count, int entryLength) {
        if (count < 0 || (long) count * entryLength > this.batch.length) {
            throw new IllegalArgumentException("Implausible entry count: " + count);
        }
    }

    /**
     * Reads a little-endian int32
     * @param data - the buffer to read from
     * @param offset - the offset to read at
     * @return the value
     */
    private static int readInt32(byte[] data, int offset) {
        if (offset < 0 || offset + 4 > data.length) {
            throw new IllegalArgumentException("Read past the end of the batch at offset " + offset);
        }
        return (data[offset] & 0xFF)
                | ((data[offset + 1] & 0xFF) << 8)
                | ((data[offset + 2] & 0xFF) << 16)
                | ((data[offset + 3] & 0xFF) << 24);
    }

    /**
     * Reads a little-endian int64
     * @param data - the buffer to read from
     * @param offset - the offset to read at
     * @return the value
     */
    private static long readInt64(byte[] data, int offset) {
        if (offset < 0 || offset + 8 > data.length) {
            throw new IllegalArgumentException("Read past the end of the batch at offset " + offset);
        }
        return (readInt32(data, offset) & 0xFFFFFFFFL) | ((long) readInt32(data, offset + 4) << 32);
    }
}
