"""
Command-line interface for the BugBounty MCP Server.
"""

import asyncio
import click
import logging
from pathlib import Path
from .server import BugBountyMCPServer
from .config import BugBountyConfig


@click.group()
@click.option('--config', '-c', help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.pass_context
def cli(ctx, config, verbose):
    """BugBounty MCP Server - Comprehensive penetration testing via chat."""
    ctx.ensure_object(dict)
    
    # Setup logging
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Load configuration
    if config:
        # Load from file
        ctx.obj['config'] = BugBountyConfig.from_file(config)
    else:
        # Use default configuration
        ctx.obj['config'] = BugBountyConfig()


@cli.command()
@click.pass_context
def serve(ctx):
    """Start the MCP server."""
    config = ctx.obj['config']
    server = BugBountyMCPServer(config)
    
    click.echo("Starting BugBounty MCP Server...")
    click.echo(f"Configuration: {config}")
    
    try:
        asyncio.run(server.run_stdio())
    except KeyboardInterrupt:
        click.echo("\nServer stopped by user.")
    except Exception as e:
        import traceback
        click.echo(f"Error starting server: {e}", err=True)
        click.echo(f"Full traceback:", err=True)
        click.echo(traceback.format_exc(), err=True)
        raise click.Abort()


@cli.command()
@click.pass_context
def validate_config(ctx):
    """Validate the configuration."""
    config = ctx.obj['config']
    
    click.echo("Validating configuration...")
    
    # Check API keys
    api_keys = [
        ('Shodan', config.api_keys.shodan),
        ('Censys ID', config.api_keys.censys_id),
        ('Censys Secret', config.api_keys.censys_secret),
        ('VirusTotal', config.api_keys.virustotal),
        ('GitHub', config.api_keys.github),
        ('SecurityTrails', config.api_keys.securitytrails),
        ('Hunter.io', config.api_keys.hunter_io),
        ('BinaryEdge', config.api_keys.binaryedge),
    ]
    
    click.echo("\nAPI Keys Status:")
    for name, key in api_keys:
        status = "✓ Configured" if key else "✗ Not configured"
        click.echo(f"  {name}: {status}")
    
    # Check tool paths
    tools = [
        ('nmap', config.tools.nmap_path),
        ('masscan', config.tools.masscan_path),
        ('nuclei', config.tools.nuclei_path),
        ('subfinder', config.tools.subfinder_path),
        ('httpx', config.tools.httpx_path),
        ('gobuster', config.tools.gobuster_path),
        ('ffuf', config.tools.ffuf_path),
        ('sqlmap', config.tools.sqlmap_path),
        ('nikto', config.tools.nikto_path),
    ]
    
    click.echo("\nTool Availability:")
    for name, path in tools:
        try:
            import shutil
            found_path = shutil.which(path)
            status = f"✓ Found at {found_path}" if found_path else "✗ Not found in PATH"
        except Exception:
            status = "✗ Not found"
        click.echo(f"  {name}: {status}")
    
    # Check directories
    dirs = [
        ('Data directory', config.data_dir),
        ('Output directory', config.output.output_dir),
        ('Wordlists directory', 'wordlists'),
    ]
    
    click.echo("\nDirectories:")
    for name, path in dirs:
        path_obj = Path(path)
        if path_obj.exists():
            status = f"✓ Exists ({path})"
        else:
            status = f"✗ Not found ({path})"
        click.echo(f"  {name}: {status}")
    
    click.echo("\nConfiguration validation complete.")


@cli.command()
@click.option('--target', '-t', required=True, help='Target to test')
@click.option('--output', '-o', help='Output file path')
@click.pass_context
def quick_scan(ctx, target, output):
    """Perform a quick security scan of a target."""
    config = ctx.obj['config']
    
    # Validate target is allowed
    if not config.is_target_allowed(target):
        click.echo(f"Error: Target {target} is not in allowed targets list", err=True)
        raise click.Abort()
    
    click.echo(f"Starting quick scan of {target}...")
    
    # This would implement a quick scan workflow
    # For now, just show what would be scanned
    scan_types = [
        "Port scan (top 1000 ports)",
        "Service enumeration",
        "Web directory scan",
        "SSL/TLS analysis",
        "Basic vulnerability checks"
    ]
    
    click.echo("\nScan components:")
    for scan_type in scan_types:
        click.echo(f"  • {scan_type}")
    
    click.echo(f"\nNote: This is a demonstration. Actual scanning requires the full MCP server.")
    
    if output:
        click.echo(f"Results would be saved to: {output}")


@cli.command()
@click.pass_context  
def list_tools(ctx):
    """List all available tools and their descriptions."""
    config = ctx.obj['config']
    server = BugBountyMCPServer(config)
    
    click.echo("Available Tools:\n")
    
    categories = [
        ("Reconnaissance", server.recon_tools),
        ("Scanning", server.scanning_tools),
        ("Vulnerability Assessment", server.vuln_tools),
        ("Web Application", server.webapp_tools),
        ("Network Security", server.network_tools),
        ("OSINT", server.osint_tools),
        ("Exploitation", server.exploit_tools),
        ("Reporting", server.reporting_tools),
    ]
    
    for category_name, tool_category in categories:
        click.echo(f"🔧 {category_name}")
        tools = tool_category.get_tools()
        
        for tool in tools:
            click.echo(f"   • {tool.name}")
            click.echo(f"     {tool.description}")
        
        click.echo()


@cli.command()
@click.option('--type', 'wordlist_type', 
              type=click.Choice(['subdomains', 'directories', 'parameters', 'files', 'all']),
              default='all', help='Type of wordlist to download')
@click.option('--source', default='seclists', help='Source repository')
def download_wordlists(wordlist_type, source):
    """Download common wordlists for scanning."""
    import requests
    from urllib.parse import urlparse
    
    click.echo(f"📥 Downloading {wordlist_type} wordlists from {source}...")
    
    # Create wordlists directory
    wordlists_dir = Path("wordlists")
    wordlists_dir.mkdir(exist_ok=True)
    
    # URLs for common wordlists with their target filenames
    wordlist_urls = {
        'subdomains': [
            ('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt', 'subdomains.txt'),
            ('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/dns-Jhaddix.txt', 'subdomains-jhaddix.txt'),
        ],
        'directories': [
            ('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/quickhits.txt', 'directories.txt'),
            ('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt', 'directory-list-medium.txt'),
            ('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt', 'directories-big.txt'),
        ],
        'parameters': [
            ('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt', 'parameters.txt'),
            ('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/objects.txt', 'api-parameters.txt'),
        ],
        'files': [
            ('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt', 'common_files.txt'),
            ('https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-files.txt', 'raft-files.txt'),
        ]
    }
    
    # Determine which wordlists to download
    if wordlist_type == 'all':
        urls_to_download = []
        for category_urls in wordlist_urls.values():
            urls_to_download.extend(category_urls)
    else:
        urls_to_download = wordlist_urls.get(wordlist_type, [])
    
    if not urls_to_download:
        click.echo(f"❌ No wordlists available for type: {wordlist_type}", err=True)
        return
    
    successful_downloads = 0
    failed_downloads = 0
    
    for url, filename in urls_to_download:
        filepath = wordlists_dir / filename
        
        click.echo(f"📥 Downloading {filename}...")
        
        try:
            # Download with requests
            response = requests.get(url, timeout=30, stream=True)
            response.raise_for_status()
            
            # Save the file
            with open(filepath, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            
            # Check file size
            file_size = filepath.stat().st_size
            if file_size > 100:  # File should be larger than 100 bytes
                file_size_mb = file_size / (1024 * 1024)
                if file_size_mb > 1:
                    size_str = f"{file_size_mb:.1f} MB"
                else:
                    size_str = f"{file_size / 1024:.1f} KB"
                
                click.echo(f"   ✅ Downloaded {filename} ({size_str})")
                successful_downloads += 1
            else:
                click.echo(f"   ❌ Downloaded {filename} but file seems too small")
                filepath.unlink()  # Remove small/empty file
                failed_downloads += 1
                
        except requests.RequestException as e:
            click.echo(f"   ❌ Failed to download {filename}: {str(e)}")
            failed_downloads += 1
        except Exception as e:
            click.echo(f"   ❌ Error saving {filename}: {str(e)}")
            failed_downloads += 1
    
    # Summary
    click.echo(f"\n📊 Download Summary:")
    click.echo(f"   ✅ Successful: {successful_downloads}")
    click.echo(f"   ❌ Failed: {failed_downloads}")
    
    if successful_downloads > 0:
        click.echo(f"\n📂 Wordlists saved in: {wordlists_dir.absolute()}")
        click.echo("🎉 Download complete! You can now use these wordlists for scanning.")
    else:
        click.echo("\n❌ No wordlists were downloaded successfully.")
        click.echo("💡 Check your internet connection and try again.")


@cli.command()
@click.option('--format', 'export_format', 
              type=click.Choice(['json', 'yaml']),
              default='yaml', help='Configuration format')
@click.option('--output', '-o', help='Output file path')
def export_config(export_format, output):
    """Export default configuration template."""
    config = BugBountyConfig()
    
    if not output:
        output = f"bugbounty_mcp_config.{export_format}"
    
    click.echo(f"Exporting default configuration to {output}...")
    
    if export_format == 'json':
        with open(output, 'w') as f:
            f.write(config.model_dump_json(indent=2))
    else:  # yaml
        try:
            import yaml
            with open(output, 'w') as f:
                yaml.dump(config.model_dump(), f, default_flow_style=False, indent=2)
        except ImportError:
            click.echo("PyYAML not installed. Please install it to export YAML config.", err=True)
            return
    
    click.echo(f"✓ Configuration exported to {output}")
    click.echo("\nEdit this file to customize your configuration, then use:")
    click.echo(f"  bugbounty-mcp --config {output} serve")


def main():
    """Main entry point."""
    cli()


if __name__ == '__main__':
    main()
