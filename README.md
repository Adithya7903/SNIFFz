# SNIFFz - Host-based Intrusion Detection System

## Overview

SNIFFz is a Rust-based Host-based Intrusion Detection System designed to monitor and analyze system activities for potential security threats. This tool provides real-time monitoring, alerting, and logging of suspicious activities.

## Features

- Real-time monitoring of system activities
- Service and network traffic analysis
- Notifications and alerts for security incidents
- Lightweight and efficient Rust implementation

## Installation

### Prerequisites

- Python (Ensure it is installed and added to PATH)

- Rust (Install via [Rustup](https://rustup.rs/))

- Git

### Steps

```sh
# Clone the repository
git clone https://github.com/adithya7903/SNIFFz.git
cd SNIFFz

# Navigate to the cargo directory
cd final/test

# Build the project
cargo build --release
```

## Usage

### Running the Tool

After building the project, you can execute the final model:

```sh
cd ../final/final_model
./final.EXE
```

### Service Monitoring

```sh
./services.sh
```

### Alert Codes

A Python script is provided to display alert codes with their descriptions. You can find the script at `final/python/exp.py`:

```sh
python final/python/exp.py
```



## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature-name`)
3. Commit your changes (`git commit -m 'Add new feature'`)
4. Push to the branch (`git push origin feature-name`)
5. Open a Pull Request

## License

This project is dual-licensed under MIT and Apache 2.0. See LICENSE file for details.

## Contact

For issues or contributions, please open an issue on GitHub.

