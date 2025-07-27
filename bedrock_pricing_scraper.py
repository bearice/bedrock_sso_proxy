#!/usr/bin/env python

import requests
import json
import re
import csv
# from bs4 import BeautifulSoup  # Not needed, using regex instead
import sys

def fetch_html_content(url):
    """Fetch HTML content from the pricing page"""
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"Error fetching HTML: {e}")
        sys.exit(1)

def fetch_json_data(url):
    """Fetch JSON pricing data"""
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching JSON: {e}")
        sys.exit(1)

def load_models_from_json():
    """Load model name to model ID mapping from models.json"""
    models_file = 'models.json'
    try:
        with open(models_file, 'r') as f:
            models_data = json.load(f)

        # Create a mapping from model name to model info
        model_mapping = {}
        for model_summary in models_data.get('modelSummaries', []):
            model_name = model_summary.get('modelName')
            model_id = model_summary.get('modelId')
            provider_name = model_summary.get('providerName')

            if model_name and model_id:
                model_mapping[model_name] = {
                    'model_id': model_id,
                    'provider': provider_name
                }

        return model_mapping
    except FileNotFoundError:
        print(f"Warning: {models_file} not found. Using fallback model ID generation.")
        return {}
    except json.JSONDecodeError as e:
        print(f"Warning: Error parsing {models_file}: {e}. Using fallback model ID generation.")
        return {}

def get_model_info_from_name(model_name, model_mapping):
    """Get model ID and provider from model name using models.json mapping"""
    # Direct lookup first
    if model_name in model_mapping:
        return model_mapping[model_name]

    # Try case-insensitive lookup
    for mapped_name, model_info in model_mapping.items():
        if mapped_name.lower() == model_name.lower():
            return model_info

    # Try partial matches for variations
    model_name_lower = model_name.lower()
    for mapped_name, model_info in model_mapping.items():
        mapped_name_lower = mapped_name.lower()
        # Handle common variations
        if (model_name_lower in mapped_name_lower or
            mapped_name_lower in model_name_lower or
            # Handle "3.5 Sonnet v2" -> "Claude 3.5 Sonnet v2"
            (model_name_lower.replace(' ', '') in mapped_name_lower.replace(' ', '')) or
            (mapped_name_lower.replace(' ', '') in model_name_lower.replace(' ', ''))):
            return model_info

    # Fallback: generate basic model ID and try to determine provider
    fallback_model_id = model_name.replace(' ', '_').replace('-', '_').replace('.', '_').replace('(', '').replace(')', '').lower()

    # Try to determine provider from model name
    provider = 'Unknown'
    if 'claude' in model_name_lower:
        provider = 'Anthropic'
    elif 'command' in model_name_lower:
        provider = 'Cohere'
    elif 'jurassic' in model_name_lower or 'jamba' in model_name_lower:
        provider = 'AI21 Labs'
    elif 'llama' in model_name_lower:
        provider = 'Meta'
    elif 'titan' in model_name_lower or 'nova' in model_name_lower:
        provider = 'Amazon'
    elif 'mistral' in model_name_lower or 'mixtral' in model_name_lower:
        provider = 'Mistral AI'
    elif 'deepseek' in model_name_lower:
        provider = 'DeepSeek'

    return {
        'model_id': fallback_model_id,
        'provider': provider
    }

def parse_table_structure(table_html):
    """Parse table structure to understand column meanings based on headers"""
    # Extract table headers
    header_pattern = r'<th[^>]*><strong>([^<]*)</strong></th>'
    headers = re.findall(header_pattern, table_html)
    
    if not headers:
        # Try alternative header pattern without <strong>
        header_pattern = r'<th[^>]*>([^<]+)</th>'
        headers = re.findall(header_pattern, table_html)
    
    # Create column mapping based on header content
    column_map = {}
    for i, header in enumerate(headers):
        header_lower = header.lower().strip()
        
        # Map header text to our standard column types
        if 'model' in header_lower and i == 0:
            column_map['model_name'] = i
        elif 'input tokens' in header_lower and 'cache' not in header_lower and 'batch' not in header_lower:
            if 'od:' in header_lower or 'price per 1,000 input tokens' == header_lower:
                column_map['input_price'] = i
        elif 'output tokens' in header_lower and 'cache' not in header_lower and 'batch' not in header_lower:
            if 'od:' in header_lower or 'price per 1,000 output tokens' == header_lower:
                column_map['output_price'] = i
        elif 'cache read' in header_lower:
            column_map['cache_read_price'] = i
        elif 'cache write' in header_lower:
            column_map['cache_write_price'] = i
        elif 'batch' in header_lower and 'input' in header_lower:
            column_map['batch_input_price'] = i
        elif 'batch' in header_lower and 'output' in header_lower:
            column_map['batch_output_price'] = i
    
    return column_map, headers

def extract_price_ids_from_row(row_html):
    """Extract all price IDs and their scale factors from a table row"""
    # Pattern to extract price IDs and optional scale factors
    price_pattern = r'\{priceOf!(?:bedrock/bedrock|bedrockmarketplace/bedrockmarketplace)!([a-zA-Z0-9_-]+)(?:!\*!([0-9.]+))?[^}]*\}'
    price_matches = re.findall(price_pattern, row_html)
    
    # Return list of tuples (price_id, scale_factor)
    price_data = []
    for price_id, scale_factor in price_matches:
        # Default scale factor is 1.0 if not specified
        scale = float(scale_factor) if scale_factor else 1.0
        if price_id not in [data[0] for data in price_data]:  # Avoid duplicates
            price_data.append((price_id, scale))
    
    return price_data

def extract_model_pricing_info(html_content, model_mapping):
    """Extract model names and their price IDs from HTML using intelligent table parsing"""
    model_pricing = {}

    # Method 1: Extract from data-pricing-markup attributes (structured data)
    markup_pattern = r'data-pricing-markup="([^"]*)"'
    markup_matches = re.findall(markup_pattern, html_content)

    print(f"Found {len(markup_matches)} data-pricing-markup attributes")

    for i, markup_content in enumerate(markup_matches):
        # Decode HTML entities
        markup_content = markup_content.replace('&quot;', '"').replace('&lt;', '<').replace('&gt;', '>')

        # Extract provider name from table header or section
        provider_match = re.search(r'<th><strong>([^<]*models)</strong></th>', markup_content)
        if not provider_match:
            provider_match = re.search(r'<strong>([^<]*models)</strong>', markup_content)
        if not provider_match:
            provider_match = re.search(r'<h3><strong>([^<]*)</strong></h3>', markup_content)

        provider = provider_match.group(1) if provider_match else f'Unknown_{i}'

        # Parse table structure to understand column meanings
        column_map, headers = parse_table_structure(markup_content)
        
        if not column_map:
            print(f"Warning: Could not parse table structure for provider {provider}")
            continue
            
        # Optional debug output
        # print(f"DEBUG: Table for {provider} has columns: {headers}")
        # print(f"DEBUG: Column mapping: {column_map}")

        # Extract all table rows with pricing data
        row_pattern = r'<tr><td>([^<]+)</td>(.+?)</tr>'
        row_matches = re.findall(row_pattern, markup_content)
        
        all_matches = []
        
        for row_match in row_matches:
            model_name = row_match[0].strip()
            row_cells = row_match[1]
            
            # Skip if this looks like a header row
            if any(keyword in model_name.lower() for keyword in ['models', 'price', 'resolution', 'modality']):
                continue
                
            # Extract all price IDs and scale factors from the row
            price_data = extract_price_ids_from_row(row_cells)
            
            if len(price_data) < len(column_map) - 1:  # -1 for model_name column
                print(f"Warning: Row for {model_name} has {len(price_data)} price IDs, expected {len(column_map) - 1}")
                # Don't skip - process with available data
            
            # Build the match based on column mapping
            match = {'model_name': model_name}
            
            # Map price IDs to appropriate columns
            for col_type, col_index in column_map.items():
                if col_type == 'model_name':
                    continue
                    
                price_index = col_index - 1  # Adjust for model_name column
                if price_index < len(price_data):
                    price_id, scale_factor = price_data[price_index]
                    # Map to our standard field names with scale factors
                    if col_type == 'input_price':
                        match['input_price_id'] = price_id
                        match['input_price_scale'] = scale_factor
                    elif col_type == 'output_price':
                        match['output_price_id'] = price_id
                        match['output_price_scale'] = scale_factor
                    elif col_type == 'cache_read_price':
                        match['cache_read_price_id'] = price_id if price_id != 'N/A' else None
                        match['cache_read_price_scale'] = scale_factor if price_id != 'N/A' else None
                    elif col_type == 'cache_write_price':
                        match['cache_write_price_id'] = price_id if price_id != 'N/A' else None
                        match['cache_write_price_scale'] = scale_factor if price_id != 'N/A' else None
                    elif col_type == 'batch_input_price':
                        match['batch_input_price_id'] = price_id if price_id != 'N/A' else None
                        match['batch_input_price_scale'] = scale_factor if price_id != 'N/A' else None
                    elif col_type == 'batch_output_price':
                        match['batch_output_price_id'] = price_id if price_id != 'N/A' else None
                        match['batch_output_price_scale'] = scale_factor if price_id != 'N/A' else None
            
            # Only add if we have at least input pricing (output is optional)
            if 'input_price_id' in match:
                # Fill in missing fields with None
                for field in ['output_price_id', 'batch_input_price_id', 'batch_output_price_id', 'cache_write_price_id', 'cache_read_price_id']:
                    if field not in match:
                        match[field] = None
                for field in ['output_price_scale', 'batch_input_price_scale', 'batch_output_price_scale', 'cache_write_price_scale', 'cache_read_price_scale']:
                    if field not in match:
                        match[field] = None
                        
                all_matches.append(match)
                print(f"DEBUG: Added {match['model_name']} to all_matches")
            else:
                print(f"DEBUG: Skipped {match['model_name']} - no input_price_id")

        for match in all_matches:
            model_name = match['model_name']
            input_price_id = match['input_price_id']
            output_price_id = match.get('output_price_id')


            # Get model info from models.json mapping
            try:
                model_info = get_model_info_from_name(model_name, model_mapping)
                model_id = model_info['model_id']
                model_provider = model_info['provider'] or provider.replace(' models', '').replace('models', '').strip()
                print(f"DEBUG: Successfully mapped {model_name} to {model_id}")
            except Exception as e:
                print(f"DEBUG: Failed to map {model_name}: {e}")
                continue

            model_pricing[model_name] = {
                'model_info': {
                    'model_id': model_id,
                    'model_name': model_name,
                    'provider': model_provider
                },
                'input_price_id': input_price_id,
                'input_price_scale': match.get('input_price_scale', 1.0),
                'output_price_id': output_price_id,
                'output_price_scale': match.get('output_price_scale', 1.0),
                'batch_input_price_id': match.get('batch_input_price_id'),
                'batch_input_price_scale': match.get('batch_input_price_scale'),
                'batch_output_price_id': match.get('batch_output_price_id'),
                'batch_output_price_scale': match.get('batch_output_price_scale'),
                'cache_write_price_id': match.get('cache_write_price_id'),
                'cache_write_price_scale': match.get('cache_write_price_scale'),
                'cache_read_price_id': match.get('cache_read_price_id'),
                'cache_read_price_scale': match.get('cache_read_price_scale')
            }


    return model_pricing

def get_region_id(region_name):
    """Convert AWS region name to region ID"""
    region_mapping = {
        'US East (N. Virginia)': 'us-east-1',
        'US East (Ohio)': 'us-east-2',
        'US West (N. California)': 'us-west-1',
        'US West (Oregon)': 'us-west-2',
        'Africa (Cape Town)': 'af-south-1',
        'Asia Pacific (Hong Kong)': 'ap-east-1',
        'Asia Pacific (Hyderabad)': 'ap-south-2',
        'Asia Pacific (Jakarta)': 'ap-southeast-3',
        'Asia Pacific (Malaysia)': 'ap-southeast-5',
        'Asia Pacific (Melbourne)': 'ap-southeast-4',
        'Asia Pacific (Mumbai)': 'ap-south-1',
        'Asia Pacific (Osaka)': 'ap-northeast-3',
        'Asia Pacific (Seoul)': 'ap-northeast-2',
        'Asia Pacific (Singapore)': 'ap-southeast-1',
        'Asia Pacific (Sydney)': 'ap-southeast-2',
        'Asia Pacific (Taipei)': 'ap-east-2',
        'Asia Pacific (Thailand)': 'ap-southeast-7',
        'Asia Pacific (Tokyo)': 'ap-northeast-1',
        'Canada (Central)': 'ca-central-1',
        'Canada West (Calgary)': 'ca-west-1',
        'Europe (Frankfurt)': 'eu-central-1',
        'Europe (Ireland)': 'eu-west-1',
        'Europe (London)': 'eu-west-2',
        'Europe (Milan)': 'eu-south-1',
        'Europe (Paris)': 'eu-west-3',
        'Europe (Spain)': 'eu-south-2',
        'Europe (Stockholm)': 'eu-north-1',
        'Europe (Zurich)': 'eu-central-2',
        'Israel (Tel Aviv)': 'il-central-1',
        'Mexico (Central)': 'mx-central-1',
        'Middle East (Bahrain)': 'me-south-1',
        'Middle East (UAE)': 'me-central-1',
        'South America (São Paulo)': 'sa-east-1',
        'AWS GovCloud (US-East)': 'us-gov-east-1',
        'AWS GovCloud (US)': 'us-gov-west-1',
        # Handle variations in naming from pricing page
        'EU (Ireland)': 'eu-west-1',
        'EU (London)': 'eu-west-2',
        'EU (Paris)': 'eu-west-3',
        'EU (Milan)': 'eu-south-1',
        'EU (Stockholm)': 'eu-north-1',
        'EU (Frankfurt)': 'eu-central-1',
        'EU (Zurich)': 'eu-central-2',
        'EU (Spain)': 'eu-south-2',
        'South America (Sao Paulo)': 'sa-east-1',
    }
    return region_mapping.get(region_name, region_name)

def get_ondemand_price(bedrock_regions, bedrockmarketplace_regions, price_id, scale_factor=1.0):
    """Get on-demand price for a specific price ID in a region from both JSON sources"""
    # Try bedrockmarketplace first
    if bedrockmarketplace_regions and price_id in bedrockmarketplace_regions:
        price_info = bedrockmarketplace_regions[price_id]
        # Only return price if it's on-demand (not batch)
        if price_info.get('price') and 'batch' not in price_info.get('rateCode', '').lower():
            raw_price = float(price_info['price'])
            # Apply the scale factor from HTML (e.g., 0.001 for per-1000-tokens conversion)
            return raw_price * scale_factor

    # Try bedrock as fallback
    if bedrock_regions and price_id in bedrock_regions:
        price_info = bedrock_regions[price_id]
        # Only return price if it's on-demand (not batch)
        if price_info.get('price') and 'batch' not in price_info.get('rateCode', '').lower():
            raw_price = float(price_info['price'])
            # Apply the scale factor from HTML (usually 1.0 for bedrock)
            return raw_price * scale_factor

    return None

def main():
    # URLs
    html_url = "https://aws.amazon.com/bedrock/pricing/"
    bedrockmarketplace_url = "https://b0.p.awsstatic.com/pricing/2.0/meteredUnitMaps/bedrockmarketplace/USD/current/bedrockmarketplace.json"
    bedrock_url = "https://b0.p.awsstatic.com/pricing/2.0/meteredUnitMaps/bedrock/USD/current/bedrock.json"

    print("Loading model mapping from models.json...")
    model_mapping = load_models_from_json()
    print(f"Loaded {len(model_mapping)} models from models.json")

    print("Fetching HTML content...")
    html_content = fetch_html_content(html_url)

    print("Fetching bedrockmarketplace JSON pricing data...")
    bedrockmarketplace_data = fetch_json_data(bedrockmarketplace_url)

    print("Fetching bedrock JSON pricing data...")
    bedrock_data = fetch_json_data(bedrock_url)

    print("Extracting model pricing information...")
    model_pricing = extract_model_pricing_info(html_content, model_mapping)

    if not model_pricing:
        print("No models found in HTML content")
        sys.exit(1)

    print(f"Found {len(model_pricing)} models in pricing tables")
    
    # Debug: List all models found
    print("Models found in pricing tables:")
    for model_name in sorted(model_pricing.keys()):
        print(f"  {model_name}")
    
    # Debug: Check specific missing models
    missing_models = ['Claude Opus 4', 'Claude Sonnet 4']
    for model_name in missing_models:
        if model_name in model_pricing:
            print(f"✅ {model_name} is in model_pricing")
        else:
            print(f"❌ {model_name} is NOT in model_pricing")

    # Create CSV data
    csv_data = []

    # Get all unique regions from both JSON sources
    all_regions = set()
    if bedrockmarketplace_data.get('regions'):
        all_regions.update(bedrockmarketplace_data['regions'].keys())
    if bedrock_data.get('regions'):
        all_regions.update(bedrock_data['regions'].keys())

    # Process each region
    for region_name in all_regions:
        bedrockmarketplace_region = bedrockmarketplace_data.get('regions', {}).get(region_name, {})
        bedrock_region = bedrock_data.get('regions', {}).get(region_name, {})

        # Convert region name to region ID
        region_id = get_region_id(region_name)
        

        for model_name, price_info in model_pricing.items():
            input_price_id = price_info['input_price_id']
            input_price_scale = price_info.get('input_price_scale', 1.0)
            output_price_id = price_info.get('output_price_id')
            output_price_scale = price_info.get('output_price_scale', 1.0)
            batch_input_price_id = price_info.get('batch_input_price_id')
            batch_input_price_scale = price_info.get('batch_input_price_scale')
            batch_output_price_id = price_info.get('batch_output_price_id')
            batch_output_price_scale = price_info.get('batch_output_price_scale')
            cache_write_price_id = price_info.get('cache_write_price_id')
            cache_write_price_scale = price_info.get('cache_write_price_scale')
            cache_read_price_id = price_info.get('cache_read_price_id')
            cache_read_price_scale = price_info.get('cache_read_price_scale')
            model_info = price_info['model_info']
            

            # Get on-demand prices from both sources
            input_price = get_ondemand_price(bedrock_region, bedrockmarketplace_region, input_price_id, input_price_scale)
            output_price = get_ondemand_price(bedrock_region, bedrockmarketplace_region, output_price_id, output_price_scale) if output_price_id else None

            # Get batch prices if available
            batch_input_price = None
            if batch_input_price_id and batch_input_price_scale:
                batch_input_price = get_ondemand_price(
                    bedrock_region, bedrockmarketplace_region, batch_input_price_id, batch_input_price_scale)

            batch_output_price = None
            if batch_output_price_id and batch_output_price_scale:
                batch_output_price = get_ondemand_price(
                    bedrock_region, bedrockmarketplace_region, batch_output_price_id, batch_output_price_scale)

            # Get cache prices if available
            cache_write_price = None
            if cache_write_price_id and cache_write_price_scale:
                cache_write_price = get_ondemand_price(
                    bedrock_region, bedrockmarketplace_region, cache_write_price_id, cache_write_price_scale)

            cache_read_price = None
            if cache_read_price_id and cache_read_price_scale:
                cache_read_price = get_ondemand_price(
                    bedrock_region, bedrockmarketplace_region, cache_read_price_id, cache_read_price_scale)

            # Only add row if both basic prices are available
            if input_price is not None and output_price is not None:
                csv_data.append({
                    'region_id': region_id,
                    'model_id': model_info['model_id'],
                    'model_name': model_info['model_name'],
                    'provider': model_info['provider'],
                    'input_price': input_price,
                    'output_price': output_price,
                    'batch_input_price': batch_input_price,
                    'batch_output_price': batch_output_price,
                    'cache_write_price': cache_write_price,
                    'cache_read_price': cache_read_price
                })

    # Write CSV file
    output_file = 'bedrock_pricing.csv'
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['region_id', 'model_id', 'model_name', 'provider', 'input_price', 'output_price',
                      'batch_input_price', 'batch_output_price', 'cache_write_price', 'cache_read_price']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for row in csv_data:
            writer.writerow(row)

    print(f"CSV file '{output_file}' created successfully with {len(csv_data)} rows")

    # Print summary
    unique_models = set(row['model_id'] for row in csv_data)
    unique_regions = set(row['region_id'] for row in csv_data)
    unique_providers = set(row['provider'] for row in csv_data)

    print(f"Summary:")
    print(f"  - {len(unique_models)} unique models")
    print(f"  - {len(unique_providers)} providers")
    print(f"  - {len(unique_regions)} regions with pricing data")
    print(f"  - {len(csv_data)} total price entries")

if __name__ == "__main__":
    main()
