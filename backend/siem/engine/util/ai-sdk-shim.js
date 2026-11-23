// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
// The last place every AI feature looks for the Anthropic SDK. When the SDK is not installed, this stands in: the local model
// (OpenAI-compatible gateway) works without it, and Claude mode answers "Anthropic SDK not installed" (util/ai-backend.js).
module.exports = require('./ai-backend').wrap(null);
