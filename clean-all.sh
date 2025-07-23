#!/bin/bash

echo "Cleaning Rust build artifacts..."
cargo clean

echo "Cleaning frontend build artifacts..."
if [ -d "frontend/dist" ]; then
    rm -rf frontend/dist
    echo "Removed frontend/dist/"
fi

if [ -d "frontend/node_modules" ]; then
    rm -rf frontend/node_modules
    echo "Removed frontend/node_modules/"
fi

echo "Complete cleanup finished!"