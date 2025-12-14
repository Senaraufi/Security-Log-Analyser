#!/bin/bash

# Download GeoLite2 City database (free version)
# Note: MaxMind now requires registration, but we'll use a direct link for testing

echo "Downloading GeoLite2 City database..."

# Create data directory
mkdir -p data

# For production, you should:
# 1. Sign up at https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
# 2. Get your license key
# 3. Download using their API

# For now, we'll create a placeholder and instructions
cat > data/README.md << 'EOF'
# GeoIP Database Setup

To enable geolocation features:

1. Sign up for a free MaxMind account:
   https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

2. Download GeoLite2-City.mmdb

3. Place it in this directory: data/GeoLite2-City.mmdb

Alternative: Use IP-API.com (no database needed, API-based)
EOF

echo "Setup complete!"
echo ""
echo "Next steps:"
echo "1. Sign up at https://dev.maxmind.com/geoip/geolite2-free-geolocation-data"
echo "2. Download GeoLite2-City.mmdb"
echo "3. Place in: data/GeoLite2-City.mmdb"
echo ""
echo "Or we can use IP-API.com (no signup needed, API-based)"
