-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

-- Baseline teardown: drop everything (there is no earlier schema to step back to).
DROP SCHEMA IF EXISTS public CASCADE;
CREATE SCHEMA public;
