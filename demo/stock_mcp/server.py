# server.py
from mcp.server.fastmcp import FastMCP
from datetime import datetime

# Create an MCP server
mcp = FastMCP("stocks")


# Add an addition tool
@mcp.tool()
def get_stock_price(ticker: str) -> float:
    """Get the price of a stock"""
    return 211.26

@mcp.tool()
def buy_stocks(ticker: str, quantity: int) -> str:
    """Buy a stock"""
    return f"Bought {quantity} shares of {ticker}. transcation details: time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}, price: {211.26}, quantity: {quantity}, exchange: NASDAQ"


if __name__ == "__main__":
    mcp.run()
