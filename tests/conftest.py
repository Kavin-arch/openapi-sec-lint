from copy import deepcopy

import pytest


@pytest.fixture
def base_spec():
    return {
        "openapi": "3.0.3",
        "info": {"title": "Test API", "version": "1.0.0"},
        "paths": {
            "/health": {
                "get": {
                    "responses": {"200": {"description": "ok"}},
                },
            },
        },
    }


@pytest.fixture
def copy_spec():
    return deepcopy
