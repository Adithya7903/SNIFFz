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
- Rust (Install via [Rustup](https://rustup.rs/))
- Git

### Steps
```sh
# Clone the repository
git clone https://github.com/adithya7903/SNIFFz.git
cd SNIFFz

# Build the project
cargo build --release

# Run the tool
cargo run
```

## Usage
Run the tool with:
```sh
cargo run
```
For service monitoring:
```sh
./services.sh
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

