#!/bin/bash
set -e

case "${1:-api}" in
    api)
        echo "Starting Goodware API on port 8443..."
        exec python3 -m goodware.api.server
        ;;
    federated)
        echo "Starting Goodware Federated server..."
        exec python3 -m goodware.federated_server.server
        ;;
    train)
        echo "Training models with NSL-KDD..."
        exec python3 -m goodware.prediction.training.train_nsl_kdd
        ;;
    shell)
        echo "Dropping to shell..."
        exec /bin/bash
        ;;
    *)
        echo "Usage: $0 [api|federated|train|shell]"
        exit 1
        ;;
esac
