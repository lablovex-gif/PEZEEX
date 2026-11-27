import { isPrivateOrInternalHost, pinnedSingleHopGet, resolvePublicUrlWithDns } from "./serverUrlAnalyzer";

const TAKEADS_RESOLVE_ENDPOINT = "https://api.takeads.com/v1/product/monetize-api/v2/resolve";
const TAKEADS_MERCHANT_ENDPOINT = "https://api.takeads.com/v1/product/monetize-api/v2/merchant";
const TAKEADS_COUPON_SEARCH_ENDPOINT = "https://api.takeads.com/v1/product/monetize-api/v1/coupon/search";
const TAKEADS_COUPON_LIST_ENDPOINT = "https://api.takeads.com/v1/product/monetize-api/v1/coupon";

const TAKEADS_CATALOG_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours
const TAKEADS_COUPON_UNAVAILABLE_TTL_MS = 30 * 60 * 1000; // 30 minutes
const TAKEADS_REQUEST_TIMEOUT_MS = 6500;
const TAKEADS_COUPON_TIMEOUT_MS = 3500;
const TAKEADS_MAX_URLS_PER_BATCH = 60;
const TAKEADS_MAX_MERCHANT_SYNC_PAGES = 60; // up to ~30,000 merchants synced in background

type RegionTag = "GLOBAL" | "US" | "CA" | "UK" | "EU" | "ME" | "APAC" | "LATAM";

interface CandidateStore {
  name: string;
  domain: string;
  probeUrl: string;
  regions: RegionTag[];
  categories: string[];
}

// Curated regional & global retail probe list verified live against PUT /v2/resolve
// + multi-hop redirect health verification so only working, active merchants are served.
const CANDIDATE_STORES: CandidateStore[] = [
  // Global / Cross-border General Marketplaces
  { name: "Amazon", domain: "amazon.com", probeUrl: "https://www.amazon.com/s?k=electronics", regions: ["GLOBAL", "US", "CA", "ME", "LATAM", "APAC"], categories: ["marketplace", "electronics", "home", "fashion", "watches", "beauty", "books", "toys", "sports"] },
  { name: "AliExpress", domain: "aliexpress.com", probeUrl: "https://www.aliexpress.com/w/wholesale-electronics.html", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC", "LATAM"], categories: ["marketplace", "electronics", "gadgets", "accessories", "home", "fashion", "watches", "tools", "toys", "kitchen", "appliances", "furniture", "decor"] },
  { name: "DHgate", domain: "dhgate.com", probeUrl: "https://www.dhgate.com/wholesale/search.do?searchkey=electronics", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC", "LATAM"], categories: ["marketplace", "wholesale", "electronics", "fashion", "watches", "gadgets", "shoes", "bags", "home", "kitchen", "decor"] },
  { name: "eBay", domain: "ebay.com", probeUrl: "https://www.ebay.com/sch/i.html?_nkw=watch", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC"], categories: ["marketplace", "electronics", "watches", "fashion", "shoes", "home", "kitchen", "tools", "toys", "books", "sports"] },
  { name: "Alibaba", domain: "alibaba.com", probeUrl: "https://www.alibaba.com/trade/search?SearchText=kitchen", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC", "LATAM"], categories: ["marketplace", "wholesale", "electronics", "home", "kitchen", "appliances", "furniture", "tools", "fashion", "watches"] },
  { name: "Temu", domain: "temu.com", probeUrl: "https://www.temu.com/search_result.html?search_key=electronics", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC", "LATAM"], categories: ["marketplace", "budget", "home", "gadgets", "fashion", "accessories", "kitchen", "toys"] },

  // Watches, Jewelry & Eyewear Specialists
  { name: "Jomashop", domain: "jomashop.com", probeUrl: "https://www.jomashop.com/search?q=watch", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC"], categories: ["watches", "eyewear", "sunglasses", "jewelry", "perfume", "fragrance", "bags"] },
  { name: "Ashford", domain: "ashford.com", probeUrl: "https://www.ashford.com/search?q=watch", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC"], categories: ["watches", "timepieces", "jewelry", "eyewear", "sunglasses"] },
  { name: "Chrono24", domain: "chrono24.com", probeUrl: "https://www.chrono24.com/search/index.htm?query=watch", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC"], categories: ["watches", "timepieces"] },
  { name: "Fossil", domain: "fossil.com", probeUrl: "https://www.fossil.com/en-us/search/?q=watch", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME"], categories: ["watches", "smartwatches", "bags", "jewelry"] },
  { name: "Swarovski", domain: "swarovski.com", probeUrl: "https://www.swarovski.com/en-US/search/?text=watch", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC"], categories: ["jewelry", "watches"] },
  { name: "Sunglass Hut", domain: "sunglasshut.com", probeUrl: "https://www.sunglasshut.com/us/search?q=sunglasses", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME"], categories: ["eyewear", "sunglasses"] },
  { name: "Ray-Ban", domain: "ray-ban.com", probeUrl: "https://www.ray-ban.com/usa/search?q=sunglasses", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME"], categories: ["eyewear", "sunglasses"] },

  // Luxury, Fashion, Shoes & Accessories
  { name: "Farfetch", domain: "farfetch.com", probeUrl: "https://www.farfetch.com/shopping/search/items.aspx?q=watch", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC"], categories: ["clothing", "apparel", "shoes", "sneakers", "footwear", "bags", "watches", "jewelry", "eyewear", "sunglasses"] },
  { name: "SSENSE", domain: "ssense.com", probeUrl: "https://www.ssense.com/en-us/men?q=shoes", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC"], categories: ["clothing", "apparel", "shoes", "sneakers", "footwear", "bags", "eyewear", "sunglasses", "jewelry"] },
  { name: "Selfridges", domain: "selfridges.com", probeUrl: "https://www.selfridges.com/US/en/cat/?freeText=watch", regions: ["GLOBAL", "UK", "US", "EU", "ME", "APAC"], categories: ["department", "clothing", "apparel", "shoes", "footwear", "bags", "watches", "jewelry", "beauty", "perfume", "fragrance", "kitchen", "decor"] },
  { name: "Cettire", domain: "cettire.com", probeUrl: "https://www.cettire.com/search?q=watch", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC"], categories: ["clothing", "apparel", "shoes", "sneakers", "footwear", "bags", "watches", "eyewear", "sunglasses"] },
  { name: "Mytheresa", domain: "mytheresa.com", probeUrl: "https://www.mytheresa.com/int/en/men/search?q=watch", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC"], categories: ["clothing", "apparel", "shoes", "sneakers", "footwear", "bags", "jewelry", "eyewear", "sunglasses"] },
  { name: "MR PORTER", domain: "mrporter.com", probeUrl: "https://www.mrporter.com/en-sa/mens/search/watch", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC"], categories: ["clothing", "apparel", "shoes", "sneakers", "footwear", "bags", "watches", "eyewear", "sunglasses"] },
  { name: "NET-A-PORTER", domain: "net-a-porter.com", probeUrl: "https://www.net-a-porter.com/en-sa/shop/search/watch", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC"], categories: ["clothing", "apparel", "shoes", "sneakers", "footwear", "bags", "watches", "jewelry", "beauty", "skincare"] },
  { name: "YesStyle", domain: "yesstyle.com", probeUrl: "https://www.yesstyle.com/en/list.html?q=skincare", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC"], categories: ["beauty", "skincare", "makeup", "haircare", "clothing", "apparel", "shoes", "bags"] },
  { name: "SHEIN", domain: "shein.com", probeUrl: "https://www.shein.com/pdsearch/fashion/", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC", "LATAM"], categories: ["clothing", "apparel", "shoes", "footwear", "bags"] },
  { name: "ASOS", domain: "asos.com", probeUrl: "https://www.asos.com/search/?q=jacket", regions: ["GLOBAL", "UK", "EU", "US", "ME"], categories: ["clothing", "apparel", "shoes", "sneakers", "footwear", "bags"] },
  { name: "LightInTheBox", domain: "lightinthebox.com", probeUrl: "https://www.lightinthebox.com/index.php?main_page=advanced_search_result&keyword=dress", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC", "LATAM"], categories: ["clothing", "apparel", "lighting", "decor"] },
  { name: "Etsy", domain: "etsy.com", probeUrl: "https://www.etsy.com/search?q=gift", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME"], categories: ["handmade", "jewelry", "watches", "decor", "art", "bags"] },

  // Sports, Sneakers & Outdoor
  { name: "Nike", domain: "nike.com", probeUrl: "https://www.nike.com/w?q=shoes", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC"], categories: ["shoes", "sneakers", "footwear", "sports", "sportswear", "running", "clothing", "apparel"] },
  { name: "Adidas", domain: "adidas.com", probeUrl: "https://www.adidas.com/us/search?q=shoes", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME"], categories: ["shoes", "sneakers", "footwear", "sports", "sportswear", "running", "clothing", "apparel"] },
  { name: "Puma", domain: "puma.com", probeUrl: "https://us.puma.com/us/en/search?q=shoes", regions: ["GLOBAL", "US", "UK", "EU", "ME"], categories: ["shoes", "sneakers", "footwear", "sports", "sportswear", "running", "clothing", "apparel"] },
  { name: "New Balance", domain: "newbalance.com", probeUrl: "https://www.newbalance.com/search/?q=shoes", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME"], categories: ["shoes", "sneakers", "footwear", "sports", "sportswear", "running"] },
  { name: "Under Armour", domain: "underarmour.com", probeUrl: "https://www.underarmour.com/en-us/search?q=shoes", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME"], categories: ["shoes", "sneakers", "footwear", "sports", "sportswear", "fitness", "running", "clothing", "apparel"] },
  { name: "Decathlon", domain: "decathlon.com", probeUrl: "https://www.decathlon.com/search?q=bike", regions: ["GLOBAL", "US", "UK", "EU", "ME"], categories: ["sports", "fitness", "camping", "cycling", "outdoor", "running", "shoes", "sneakers", "footwear", "sportswear"] },

  // Beauty, Perfume & Health
  { name: "iHerb", domain: "iherb.com", probeUrl: "https://www.iherb.com/search?kw=vitamins", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC", "LATAM"], categories: ["health", "vitamins", "supplements", "nutrition", "beauty", "skincare", "haircare", "pharmacy", "baby"] },
  { name: "Sephora", domain: "sephora.com", probeUrl: "https://www.sephora.com/search?keyword=perfume", regions: ["US", "CA"], categories: ["beauty", "perfume", "fragrance", "makeup", "skincare", "haircare", "cosmetics"] },
  { name: "Sephora", domain: "sephora.me", probeUrl: "https://www.sephora.me/sa-en/search?q=perfume", regions: ["ME"], categories: ["beauty", "perfume", "fragrance", "makeup", "skincare", "haircare", "cosmetics"] },
  { name: "Lookfantastic", domain: "lookfantastic.com", probeUrl: "https://www.lookfantastic.com/search/?q=skincare", regions: ["GLOBAL", "UK", "EU", "ME", "US"], categories: ["beauty", "skincare", "perfume", "fragrance", "makeup", "haircare", "cosmetics"] },
  { name: "Cult Beauty", domain: "cultbeauty.com", probeUrl: "https://www.cultbeauty.com/search/?q=skincare", regions: ["GLOBAL", "UK", "EU", "ME", "US"], categories: ["beauty", "skincare", "makeup", "haircare", "perfume", "fragrance", "cosmetics"] },
  { name: "FragranceX", domain: "fragrancex.com", probeUrl: "https://www.fragrancex.com/search/search_results?stext=perfume", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME"], categories: ["perfume", "fragrance"] },
  { name: "FragranceNet", domain: "fragrancenet.com", probeUrl: "https://www.fragrancenet.com/s/perfume", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME"], categories: ["perfume", "fragrance", "skincare", "beauty"] },

  // Electronics, Tech, Audio, Gaming & Appliances
  { name: "Samsung", domain: "samsung.com", probeUrl: "https://www.samsung.com/sa/aisearch/?searchvalue=phone", regions: ["GLOBAL", "US", "UK", "EU", "ME"], categories: ["phones", "tablets", "tv", "appliances", "smartwatches", "wearables", "earbuds", "audio", "monitors", "chargers", "cables"] },
  { name: "Lenovo", domain: "lenovo.com", probeUrl: "https://www.lenovo.com/sa/en/search?text=laptop", regions: ["GLOBAL", "US", "UK", "EU", "ME"], categories: ["laptops", "computers", "tablets", "monitors", "gaming"] },
  { name: "HP", domain: "hp.com", probeUrl: "https://www.hp.com/us-en/shop/sitesearch?keyword=laptop", regions: ["GLOBAL", "US", "UK", "EU", "ME"], categories: ["laptops", "computers", "printers", "monitors"] },
  { name: "Dell", domain: "dell.com", probeUrl: "https://www.dell.com/en-us/search/laptop", regions: ["GLOBAL", "US", "UK", "EU", "ME"], categories: ["laptops", "computers", "monitors", "gaming"] },
  { name: "Anker", domain: "anker.com", probeUrl: "https://www.anker.com/search?q=charger", regions: ["GLOBAL", "US", "UK", "EU", "ME"], categories: ["chargers", "powerbank", "cables", "audio", "earbuds", "headphones", "speakers", "projectors"] },
  { name: "Bose", domain: "bose.com", probeUrl: "https://www.bose.com/search?q=headphones", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME"], categories: ["audio", "headphones", "earbuds", "speakers"] },
  { name: "JBL", domain: "jbl.com", probeUrl: "https://www.jbl.com/search?q=headphones", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME"], categories: ["audio", "headphones", "earbuds", "speakers"] },
  { name: "Logitech", domain: "logitech.com", probeUrl: "https://www.logitech.com/en-us/search?q=mouse", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME"], categories: ["computers", "laptops", "gaming", "audio", "headphones", "cameras"] },
  { name: "Razer", domain: "razer.com", probeUrl: "https://www.razer.com/search/mouse", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME"], categories: ["gaming", "laptops", "computers", "audio", "headphones"] },
  { name: "B&H Photo", domain: "bhphotovideo.com", probeUrl: "https://www.bhphotovideo.com/c/search?q=camera", regions: ["GLOBAL", "US", "CA", "ME"], categories: ["cameras", "drones", "photography", "audio", "headphones", "laptops", "computers", "monitors", "tv", "projectors"] },
  { name: "Dyson", domain: "dyson.com", probeUrl: "https://www.dyson.com/search-results?q=vacuum", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME"], categories: ["appliances", "vacuums", "haircare"] },
  { name: "Banggood", domain: "banggood.com", probeUrl: "https://www.banggood.com/search/electronics.html", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME", "APAC", "LATAM"], categories: ["phones", "tablets", "laptops", "computers", "audio", "headphones", "chargers", "powerbank", "cables", "tools", "rc", "drones", "cameras", "smartwatches", "wearables", "projectors", "outdoor", "auto", "kitchen", "appliances", "lighting"] },
  { name: "Geekbuying", domain: "geekbuying.com", probeUrl: "https://www.geekbuying.com/search?keyword=electronics", regions: ["GLOBAL", "US", "UK", "EU", "ME"], categories: ["phones", "tablets", "laptops", "computers", "audio", "headphones", "chargers", "powerbank", "ebikes", "3d printers", "smartwatches", "wearables", "projectors", "appliances", "vacuums", "kitchen"] },

  // Home, Toys & Kids
  { name: "IKEA", domain: "ikea.com", probeUrl: "https://www.ikea.com/sa/en/search/?q=chair", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME"], categories: ["furniture", "bedding", "kitchen", "cookware", "decor", "lighting", "rugs"] },
  { name: "LEGO", domain: "lego.com", probeUrl: "https://www.lego.com/en-us/search?q=star+wars", regions: ["GLOBAL", "US", "CA", "UK", "EU", "ME"], categories: ["toys", "kids"] },

  // North America (US & CA)
  { name: "Walmart", domain: "walmart.com", probeUrl: "https://www.walmart.com/search?q=electronics", regions: ["US", "CA"], categories: ["marketplace", "electronics", "home", "grocery", "toys", "fashion", "watches", "appliances"] },
  { name: "Target", domain: "target.com", probeUrl: "https://www.target.com/s?searchTerm=electronics", regions: ["US"], categories: ["marketplace", "home", "electronics", "fashion", "watches", "beauty", "toys", "baby"] },
  { name: "Best Buy", domain: "bestbuy.com", probeUrl: "https://www.bestbuy.com/site/searchpage.jsp?st=electronics", regions: ["US"], categories: ["laptops", "computers", "phones", "tablets", "tv", "projectors", "gaming", "audio", "headphones", "speakers", "chargers", "cables", "cameras", "drones", "smartwatches", "wearables", "appliances"] },
  { name: "Newegg", domain: "newegg.com", probeUrl: "https://www.newegg.com/p/pl?d=laptop", regions: ["US", "CA"], categories: ["computers", "pc parts", "laptops", "gaming", "monitors"] },
  { name: "Home Depot", domain: "homedepot.com", probeUrl: "https://www.homedepot.com/s/tools", regions: ["US"], categories: ["tools", "hardware", "home improvement", "appliances", "garden", "lighting"] },
  { name: "Lowe's", domain: "lowes.com", probeUrl: "https://www.lowes.com/search?searchTerm=tools", regions: ["US"], categories: ["tools", "hardware", "home improvement", "appliances", "garden", "lighting"] },
  { name: "Macy's", domain: "macys.com", probeUrl: "https://www.macys.com/shop/featured/shoes", regions: ["US"], categories: ["department", "clothing", "apparel", "shoes", "footwear", "bags", "watches", "jewelry", "perfume", "fragrance", "beauty", "kitchen", "bedding"] },
  { name: "Nordstrom", domain: "nordstrom.com", probeUrl: "https://www.nordstrom.com/sr?keyword=shoes", regions: ["US"], categories: ["department", "clothing", "apparel", "shoes", "footwear", "bags", "watches", "jewelry", "beauty", "perfume", "fragrance", "eyewear"] },
  { name: "Wayfair", domain: "wayfair.com", probeUrl: "https://www.wayfair.com/keyword.php?keyword=chair", regions: ["US", "CA", "UK"], categories: ["furniture", "bedding", "decor", "lighting", "rugs", "kitchen", "cookware"] },
  { name: "Amazon Canada", domain: "amazon.ca", probeUrl: "https://www.amazon.ca/s?k=electronics", regions: ["CA"], categories: ["marketplace", "electronics", "home", "fashion", "watches", "beauty"] },
  { name: "Best Buy Canada", domain: "bestbuy.ca", probeUrl: "https://www.bestbuy.ca/en-ca/search?search=electronics", regions: ["CA"], categories: ["laptops", "computers", "phones", "tablets", "tv", "gaming", "audio", "headphones", "chargers", "cameras", "smartwatches", "wearables", "appliances"] },

  // Middle East & North Africa
  { name: "Noon", domain: "noon.com", probeUrl: "https://www.noon.com/saudi-en/search/?q=electronics", regions: ["ME"], categories: ["marketplace", "electronics", "phones", "fashion", "watches", "beauty", "home", "perfume", "appliances", "toys", "sports"] },
  { name: "Amazon Saudi", domain: "amazon.sa", probeUrl: "https://www.amazon.sa/s?k=electronics", regions: ["ME"], categories: ["marketplace", "electronics", "phones", "home", "fashion", "watches", "beauty", "appliances", "toys", "books"] },
  { name: "Amazon UAE", domain: "amazon.ae", probeUrl: "https://www.amazon.ae/s?k=electronics", regions: ["ME"], categories: ["marketplace", "electronics", "phones", "home", "fashion", "watches", "beauty", "appliances", "toys"] },
  { name: "Jarir Bookstore", domain: "jarir.com", probeUrl: "https://www.jarir.com/sa-en/catalogsearch/result?q=laptop", regions: ["ME"], categories: ["laptops", "computers", "phones", "tablets", "gaming", "audio", "headphones", "speakers", "chargers", "cables", "smartwatches", "wearables", "printers", "monitors", "books", "stationery", "cameras"] },
  { name: "eXtra", domain: "extra.com", probeUrl: "https://www.extra.com/en-sa/search?text=laptop", regions: ["ME"], categories: ["laptops", "computers", "phones", "tablets", "tv", "appliances", "vacuums", "kitchen", "gaming", "audio", "headphones", "speakers", "smartwatches", "wearables", "cameras", "chargers"] },
  { name: "Namshi", domain: "namshi.com", probeUrl: "https://www.namshi.com/saudi-en/search/?q=shoes", regions: ["ME"], categories: ["shoes", "sneakers", "footwear", "clothing", "apparel", "bags", "watches", "eyewear", "sunglasses", "beauty", "sportswear"] },
  { name: "6thStreet", domain: "6thstreet.com", probeUrl: "https://en-sa.6thstreet.com/search?q=shoes", regions: ["ME"], categories: ["shoes", "sneakers", "footwear", "bags", "clothing", "apparel", "watches", "eyewear", "sunglasses", "beauty"] },
  { name: "Ounass", domain: "saudi.ounass.com", probeUrl: "https://saudi.ounass.com/search?q=watch", regions: ["ME"], categories: ["clothing", "apparel", "shoes", "sneakers", "footwear", "bags", "watches", "jewelry", "beauty", "perfume", "fragrance", "eyewear"] },
  { name: "Bloomingdale's", domain: "bloomingdales.sa", probeUrl: "https://bloomingdales.sa/search?q=watch", regions: ["ME"], categories: ["department", "clothing", "apparel", "shoes", "footwear", "bags", "watches", "jewelry", "beauty", "perfume", "fragrance", "decor", "kitchen"] },
  { name: "Sun & Sand Sports", domain: "sunandsandsports.com", probeUrl: "https://en-sa.sssports.com/search?q=shoes", regions: ["ME"], categories: ["shoes", "sneakers", "footwear", "sports", "sportswear", "fitness", "running", "clothing"] },
  { name: "Home Centre", domain: "homecentre.com", probeUrl: "https://www.homecentre.com/sa/en/search?q=chair", regions: ["ME"], categories: ["furniture", "bedding", "kitchen", "cookware", "decor", "lighting", "rugs"] },
  { name: "Max Fashion", domain: "maxfashion.com", probeUrl: "https://www.maxfashion.com/sa/en/search?q=shoes", regions: ["ME"], categories: ["clothing", "apparel", "shoes", "footwear", "bags", "decor"] },
  { name: "Centrepoint", domain: "centrepointstores.com", probeUrl: "https://www.centrepointstores.com/sa/en/search?q=shoes", regions: ["ME"], categories: ["clothing", "apparel", "shoes", "footwear", "bags", "beauty", "baby", "kids", "toys", "decor"] },
  { name: "Faces", domain: "faces.sa", probeUrl: "https://www.faces.sa/en/search?q=perfume", regions: ["ME"], categories: ["perfume", "fragrance", "beauty", "skincare", "makeup", "haircare", "cosmetics"] },
  { name: "VogaCloset", domain: "vogacloset.com", probeUrl: "https://vogacloset.com/saudi-arabia/catalogsearch/result/?q=dress", regions: ["ME"], categories: ["clothing", "apparel", "shoes", "footwear", "bags", "beauty"] },
  { name: "Styli", domain: "stylishop.com", probeUrl: "https://stylishop.com/sa/en/search?q=dress", regions: ["ME"], categories: ["clothing", "apparel", "shoes", "footwear", "bags", "beauty"] },
  { name: "Sivvi", domain: "sivvi.com", probeUrl: "https://www.sivvi.com/saudi-en/search?q=shoes", regions: ["ME"], categories: ["clothing", "apparel", "shoes", "sneakers", "footwear", "bags", "sportswear"] },
  { name: "Nice One", domain: "niceonesa.com", probeUrl: "https://niceonesa.com/en/search?q=perfume", regions: ["ME"], categories: ["beauty", "perfume", "fragrance", "makeup", "skincare", "haircare", "cosmetics"] },
  { name: "Golden Scent", domain: "goldenscent.com", probeUrl: "https://www.goldenscent.com/search?q=perfume", regions: ["ME"], categories: ["perfume", "fragrance", "beauty", "skincare", "makeup"] },
  { name: "Level Shoes", domain: "levelshoes.com", probeUrl: "https://www.levelshoes.com/catalogsearch/result/?q=sneakers", regions: ["ME"], categories: ["shoes", "sneakers", "footwear", "bags"] },
  { name: "Mumzworld", domain: "mumzworld.com", probeUrl: "https://www.mumzworld.com/en/search?q=stroller", regions: ["ME"], categories: ["baby", "kids", "toys"] },
  { name: "Trendyol", domain: "trendyol.com", probeUrl: "https://www.trendyol.com/sr?q=shoes", regions: ["ME", "EU"], categories: ["clothing", "apparel", "shoes", "sneakers", "footwear", "bags", "beauty"] },
  { name: "Jumia", domain: "jumia.com.eg", probeUrl: "https://www.jumia.com.eg/catalog/?q=electronics", regions: ["ME"], categories: ["marketplace", "electronics", "phones", "fashion", "watches", "home"] },

  // UK & Europe
  { name: "Amazon UK", domain: "amazon.co.uk", probeUrl: "https://www.amazon.co.uk/s?k=electronics", regions: ["UK"], categories: ["marketplace", "electronics", "home", "fashion", "watches", "beauty"] },
  { name: "Currys", domain: "currys.co.uk", probeUrl: "https://www.currys.co.uk/search?q=laptop", regions: ["UK"], categories: ["laptops", "computers", "phones", "tablets", "tv", "projectors", "appliances", "gaming", "audio", "headphones", "chargers", "cameras", "smartwatches", "wearables"] },
  { name: "Argos", domain: "argos.co.uk", probeUrl: "https://www.argos.co.uk/search/electronics/", regions: ["UK"], categories: ["marketplace", "electronics", "home", "toys", "furniture", "watches", "jewelry"] },
  { name: "Amazon Germany", domain: "amazon.de", probeUrl: "https://www.amazon.de/s?k=electronics", regions: ["EU"], categories: ["marketplace", "electronics", "home", "fashion", "watches"] },
  { name: "Amazon France", domain: "amazon.fr", probeUrl: "https://www.amazon.fr/s?k=electronics", regions: ["EU"], categories: ["marketplace", "electronics", "home", "fashion", "watches"] },
  { name: "Amazon Spain", domain: "amazon.es", probeUrl: "https://www.amazon.es/s?k=electronics", regions: ["EU"], categories: ["marketplace", "electronics", "home", "fashion", "watches"] },
  { name: "Amazon Italy", domain: "amazon.it", probeUrl: "https://www.amazon.it/s?k=electronics", regions: ["EU"], categories: ["marketplace", "electronics", "home", "fashion", "watches"] },
  { name: "Otto", domain: "otto.de", probeUrl: "https://www.otto.de/suche/electronics/", regions: ["EU"], categories: ["marketplace", "fashion", "furniture", "electronics", "home", "watches"] },
  { name: "MediaMarkt", domain: "mediamarkt.de", probeUrl: "https://www.mediamarkt.de/de/search.html?query=electronics", regions: ["EU"], categories: ["laptops", "computers", "phones", "tablets", "tv", "projectors", "gaming", "audio", "headphones", "chargers", "cameras", "smartwatches", "wearables", "appliances"] },
  { name: "Cdiscount", domain: "cdiscount.com", probeUrl: "https://www.cdiscount.com/search/10/electronics.html", regions: ["EU"], categories: ["marketplace", "electronics", "home", "appliances", "watches"] },
  { name: "Fnac", domain: "fnac.com", probeUrl: "https://www.fnac.com/SearchResult/ResultList.aspx?Search=electronics", regions: ["EU"], categories: ["books", "gaming", "audio", "headphones", "computers", "laptops", "phones", "cameras", "tv"] },
  { name: "Bol.com", domain: "bol.com", probeUrl: "https://www.bol.com/nl/nl/s/?searchtext=electronics", regions: ["EU"], categories: ["marketplace", "electronics", "books", "home", "toys", "watches"] },
  { name: "Zalando", domain: "zalando.de", probeUrl: "https://www.zalando.de/katalog/?q=shoes", regions: ["EU"], categories: ["shoes", "sneakers", "footwear", "clothing", "apparel", "sportswear", "bags"] },

  // APAC & LATAM
  { name: "Amazon Australia", domain: "amazon.com.au", probeUrl: "https://www.amazon.com.au/s?k=electronics", regions: ["APAC"], categories: ["marketplace", "electronics", "home", "fashion", "watches"] },
  { name: "Amazon Japan", domain: "amazon.co.jp", probeUrl: "https://www.amazon.co.jp/s?k=electronics", regions: ["APAC"], categories: ["marketplace", "electronics", "home", "fashion", "watches"] },
  { name: "Amazon India", domain: "amazon.in", probeUrl: "https://www.amazon.in/s?k=electronics", regions: ["APAC"], categories: ["marketplace", "electronics", "home", "fashion", "watches"] },
  { name: "Flipkart", domain: "flipkart.com", probeUrl: "https://www.flipkart.com/search?q=electronics", regions: ["APAC"], categories: ["marketplace", "electronics", "phones", "fashion", "watches", "home"] },
  { name: "Mercado Libre", domain: "mercadolibre.com.mx", probeUrl: "https://listado.mercadolibre.com.mx/electronics", regions: ["LATAM"], categories: ["marketplace", "electronics", "home", "fashion", "watches"] },
  { name: "Amazon Brazil", domain: "amazon.com.br", probeUrl: "https://www.amazon.com.br/s?k=electronics", regions: ["LATAM"], categories: ["marketplace", "electronics", "home", "fashion", "watches"] },
];

const ME_COUNTRIES = new Set(["SA", "AE", "EG", "KW", "QA", "BH", "OM", "JO", "LB", "IQ", "MA", "DZ", "TN", "TR"]);
const EU_COUNTRIES = new Set([
  "DE", "FR", "ES", "IT", "NL", "PL", "SE", "BE", "AT", "CH", "CZ", "DK", "NO", "FI",
  "GR", "HU", "RO", "UA", "BG", "HR", "SK", "LT", "SI", "LV", "EE", "AL", "BA", "IS", "PT", "IE",
]);
const APAC_COUNTRIES = new Set(["IN", "JP", "KR", "AU", "NZ", "SG", "MY", "PH", "ID", "TH", "VN", "CN", "HK", "TW"]);
const LATAM_COUNTRIES = new Set(["BR", "MX", "AR", "CL", "CO", "PE", "UY", "EC"]);

// True general multi-category marketplaces that legitimately sell almost all physical retail categories
const TRUE_GENERAL_MARKETPLACES = new Set([
  "amazon.com", "amazon.sa", "amazon.ae", "amazon.co.uk", "amazon.de", "amazon.fr",
  "amazon.ca", "amazon.es", "amazon.it", "amazon.in", "amazon.com.au", "amazon.co.jp",
  "amazon.com.br", "amazon.eg", "amazon.nl", "amazon.com.tr",
  "noon.com", "aliexpress.com", "dhgate.com", "ebay.com", "alibaba.com",
  "walmart.com", "walmart.ca", "target.com",
  "argos.co.uk", "otto.de", "bol.com", "cdiscount.com",
  "flipkart.com", "mercadolibre.com.mx", "mercadolivre.com.br",
  "jumia.com.eg", "jumia.ma", "carrefourksa.com", "carrefouruae.com", "luluhypermarket.com",
]);

const MAJOR_RETAIL_DOMAINS = new Set([
  ...TRUE_GENERAL_MARKETPLACES,
  "jarir.com", "extra.com", "sephora.me", "saudi.ounass.com",
  "jomashop.com", "ashford.com", "chrono24.com", "fossil.com", "swarovski.com", "farfetch.com",
  "ssense.com", "selfridges.com", "cettire.com", "mytheresa.com", "mrporter.com", "net-a-porter.com",
  "yesstyle.com", "fragrancenet.com", "bloomingdales.sa", "homecentre.com", "sunandsandsports.com",
  "maxfashion.com", "centrepointstores.com", "faces.sa",
  "iherb.com", "sephora.com", "lookfantastic.com",
  "cultbeauty.com", "fragrancex.com", "niceonesa.com", "goldenscent.com",
  "nike.com", "adidas.com", "puma.com", "newbalance.com", "underarmour.com", "decathlon.com",
  "samsung.com", "lenovo.com", "hp.com", "dell.com", "anker.com", "bose.com", "jbl.com",
  "logitech.com", "razer.com", "bhphotovideo.com", "dyson.com", "banggood.com", "geekbuying.com",
  "bestbuy.com", "bestbuy.ca", "newegg.com", "currys.co.uk", "mediamarkt.de", "fnac.com",
  "ikea.com", "wayfair.com", "homedepot.com", "lowes.com", "macys.com", "nordstrom.com",
  "namshi.com", "6thstreet.com", "sivvi.com", "vogacloset.com", "stylishop.com", "levelshoes.com",
  "asos.com", "trendyol.com", "zalando.de", "etsy.com", "mumzworld.com", "lego.com",
  "sunglasshut.com", "ray-ban.com",
]);

// Non-retail service categories from /v2/merchant that should never pollute physical product searches
const NON_RETAIL_SERVICE_PATTERN =
  /\b(vpn|antivirus|web hosting|cloud hosting|domain registrar|flights?|airlines?|hotels?|hostels?|car rental|travel insurance|crypto|forex|trading|casino|betting|gambling|dating|loan|mortgage|credit card|bank(?:ing)?|insurance|ticketmaster|stubhub|saas|vps|proxy)\b/i;

function getRegionForCountry(countryCode: string): RegionTag {
  const cc = (countryCode || "US").toUpperCase();
  if (cc === "US") return "US";
  if (cc === "CA") return "CA";
  if (cc === "GB" || cc === "UK") return "UK";
  if (ME_COUNTRIES.has(cc)) return "ME";
  if (EU_COUNTRIES.has(cc)) return "EU";
  if (APAC_COUNTRIES.has(cc)) return "APAC";
  if (LATAM_COUNTRIES.has(cc)) return "LATAM";
  return "GLOBAL";
}

export function getTakeadsPublicKey(): string {
  return (process.env.TAKEADS_PUBLIC_KEY || "").trim();
}

export function getTakeadsSubId(): string {
  const raw = (process.env.TAKEADS_SUB_ID || "pezeex").trim();
  const clean = raw.replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 64);
  return clean || "pezeex";
}

export function isTakeadsConfigured(): boolean {
  return getTakeadsPublicKey().length > 0;
}

export function normalizeDomain(raw: string): string {
  let d = (raw || "").toLowerCase().trim();
  if (!d) return "";
  d = d.replace(/^https?:\/\//i, "").split("/")[0].split("?")[0].split("#")[0];
  d = d.replace(/:\d+$/, "").replace(/^www\./, "").replace(/\.$/, "");
  if (!d || d.length > 120 || isPrivateOrInternalHost(d)) return "";
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(d)) {
    return "";
  }
  return d;
}

function extractBrandRootLabel(domain: string): string {
  const norm = normalizeDomain(domain);
  if (!norm) return "";
  const parts = norm.split(".");
  if (parts.length < 2) return norm;
  const last = parts[parts.length - 1];
  const secondLast = parts[parts.length - 2];
  // Handle ccTLDs like .co.uk, .com.sa, .com.au, .com.mx, .com.br, .com.eg
  if (parts.length >= 3 && last.length === 2 && (secondLast === "co" || secondLast === "com" || secondLast === "net" || secondLast === "org")) {
    return parts[parts.length - 3];
  }
  return secondLast;
}

function hostMatchesMerchantDomain(host: string, merchantDomain: string): boolean {
  const h = normalizeDomain(host);
  const m = normalizeDomain(merchantDomain);
  if (!h || !m) return false;
  if (h === m || h.endsWith("." + m)) return true;
  const hBrand = extractBrandRootLabel(h);
  const mBrand = extractBrandRootLabel(m);
  return hBrand.length >= 3 && hBrand === mBrand;
}

function cleanApiText(raw: unknown, maxLen: number): string {
  if (typeof raw !== "string" && typeof raw !== "number") return "";
  return String(raw)
    .replace(/[\u0000-\u001F\u007F]/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, maxLen);
}

function isValidHttpsUrl(rawUrl: unknown): rawUrl is string {
  if (typeof rawUrl !== "string") return false;
  const trimmed = rawUrl.trim();
  if (!trimmed || trimmed.length > 1200 || /[\u0000-\u001F\u007F]/.test(trimmed)) {
    return false;
  }
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "https:") return false;
    if (parsed.username || parsed.password) return false;
    if (parsed.port && parsed.port !== "443") return false;
    if (!parsed.hostname || isPrivateOrInternalHost(parsed.hostname)) return false;
    return true;
  } catch {
    return false;
  }
}

function isSafePublicHttpUrl(rawUrl: string): boolean {
  if (!rawUrl || rawUrl.length > 2000 || /[\u0000-\u001F\u007F]/.test(rawUrl)) return false;
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return false;
    if (parsed.username || parsed.password) return false;
    if (parsed.port && parsed.port !== "443" && !(parsed.protocol === "http:" && parsed.port === "80")) {
      return false;
    }
    if (!parsed.hostname || isPrivateOrInternalHost(parsed.hostname)) return false;
    return true;
  } catch {
    return false;
  }
}

function isGenuineTakeadsAffiliateLink(
  rawUrl: unknown,
  merchantDomain?: string,
  originalIri?: string
): rawUrl is string {
  if (!isValidHttpsUrl(rawUrl)) return false;
  const trimmed = rawUrl.trim();
  if (originalIri && trimmed === originalIri.trim()) return false;
  try {
    const host = normalizeDomain(new URL(trimmed).hostname);
    if (!host) return false;
    // A genuine Takeads commission link must route through a tracking redirector (e.g. tatrck.com),
    // never directly to the merchant's own raw store domain without affiliate tracking.
    if (merchantDomain && hostMatchesMerchantDomain(host, merchantDomain)) {
      return false;
    }
    return true;
  } catch {
    return false;
  }
}

export interface TakeadsMerchant {
  id: string;
  name: string;
  domain: string;
  domains: string[];
  countryCodes: string[]; // Empty array means explicitly global / unrestricted
  categories: string[];
  description: string;
  trackingLink: string;
  isDeeplinkEnabled: boolean;
  hasVerifiedCommission: boolean;
  maxCommissionValue: number;
  commissionCountries: string[]; // Empty means commission applies to merchant's countryCodes / global
  source: "merchant-api" | "resolve-probe";
}

export interface TakeadsDeal {
  id: string;
  merchantId: string;
  merchantName: string;
  domain: string;
  title: string;
  description: string;
  code: string;
  discount: string;
  trackingLink: string;
  url: string;
  endsAt: string;
}

export interface TakeadsResolveResult {
  ok: boolean;
  authError?: boolean;
  linksByIri: Map<string, string>;
}

let hasLoggedAuthWarning = false;

export async function resolveTakeadsUrls(
  urls: string[],
  signal?: AbortSignal
): Promise<TakeadsResolveResult> {
  const linksByIri = new Map<string, string>();
  const publicKey = getTakeadsPublicKey();
  if (!publicKey) {
    return { ok: false, linksByIri };
  }

  const uniqueUrls: string[] = [];
  const seen = new Set<string>();
  for (const u of urls) {
    if (typeof u !== "string") continue;
    const trimmed = u.trim();
    if (!trimmed || !trimmed.startsWith("https://") || seen.has(trimmed)) continue;
    seen.add(trimmed);
    uniqueUrls.push(trimmed);
  }

  if (uniqueUrls.length === 0) {
    return { ok: true, linksByIri };
  }

  const subId = getTakeadsSubId();

  for (let offset = 0; offset < uniqueUrls.length; offset += TAKEADS_MAX_URLS_PER_BATCH) {
    if (signal?.aborted) {
      return { ok: false, linksByIri };
    }

    const batch = uniqueUrls.slice(offset, offset + TAKEADS_MAX_URLS_PER_BATCH);
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), TAKEADS_REQUEST_TIMEOUT_MS);
    const onParentAbort = () => controller.abort();
    signal?.addEventListener("abort", onParentAbort, { once: true });

    try {
      const response = await fetch(TAKEADS_RESOLVE_ENDPOINT, {
        method: "PUT",
        redirect: "error",
        headers: {
          Authorization: `Bearer ${publicKey}`,
          "Content-Type": "application/json",
          Accept: "application/json",
        },
        body: JSON.stringify({
          iris: batch,
          subId,
        }),
        signal: controller.signal,
      });

      if (response.status === 401 || response.status === 403) {
        if (!hasLoggedAuthWarning) {
          hasLoggedAuthWarning = true;
          console.warn(
            "[Takeads] Authentication failed (HTTP " +
              response.status +
              "). Ensure TAKEADS_PUBLIC_KEY is set to your Platform API Public Key (from Platform settings -> Platform API)."
          );
        }
        return { ok: false, authError: true, linksByIri };
      }

      if (!response.ok) {
        console.warn(`[Takeads] Resolve API returned HTTP ${response.status}`);
        return { ok: false, linksByIri };
      }

      const payload: any = await response.json();
      const entries = Array.isArray(payload?.data) ? payload.data : [];
      for (const entry of entries) {
        const iri = typeof entry?.iri === "string" ? entry.iri.trim() : "";
        const trackingLink = entry?.trackingLink;
        const iriDomain = iri ? normalizeDomain(iri) : "";
        if (iri && isGenuineTakeadsAffiliateLink(trackingLink, iriDomain, iri)) {
          linksByIri.set(iri, trackingLink.trim());
        }
      }
    } catch (err: any) {
      if (signal?.aborted) {
        return { ok: false, linksByIri };
      }
      console.warn("[Takeads] Resolve request failed:", err?.message || err);
      return { ok: false, linksByIri };
    } finally {
      clearTimeout(timeoutId);
      signal?.removeEventListener("abort", onParentAbort);
    }
  }

  return { ok: true, linksByIri };
}

function parseNumericCommissionValue(raw: unknown): number | null {
  if (typeof raw === "number" && Number.isFinite(raw)) {
    return raw;
  }
  if (typeof raw === "string") {
    const cleaned = raw.replace(/,/g, ".").trim();
    const match = cleaned.match(/-?\d+(?:\.\d+)?/);
    if (match) {
      const parsed = Number.parseFloat(match[0]);
      if (Number.isFinite(parsed)) return parsed;
    }
  }
  return null;
}

function extractRawMerchantDomains(raw: any): string[] {
  const rawDomains: string[] = [];
  if (typeof raw?.defaultDomain === "string") rawDomains.push(raw.defaultDomain);
  if (typeof raw?.domain === "string") rawDomains.push(raw.domain);
  if (Array.isArray(raw?.domains)) {
    for (const d of raw.domains) {
      if (typeof d === "string") rawDomains.push(d);
      else if (d && typeof d.domain === "string") rawDomains.push(d.domain);
    }
  }
  if (typeof raw?.website === "string") rawDomains.push(raw.website);

  const domains: string[] = [];
  const seenDom = new Set<string>();
  for (const rd of rawDomains) {
    const norm = normalizeDomain(rd);
    if (norm && !seenDom.has(norm)) {
      seenDom.add(norm);
      domains.push(norm);
    }
  }
  return domains;
}

interface ParsedMerchantResult {
  merchant: TakeadsMerchant | null;
  excludedDomains: string[];
}

function parseMerchantObject(raw: any): ParsedMerchantResult {
  if (!raw || typeof raw !== "object") return { merchant: null, excludedDomains: [] };

  const domains = extractRawMerchantDomains(raw);
  if (domains.length === 0) return { merchant: null, excludedDomains: [] };

  const statusLower = typeof raw.status === "string" ? raw.status.toLowerCase().trim() : "";
  if (
    raw.isActive === false ||
    raw.active === false ||
    raw.isMonetizable === false ||
    raw.monetizable === false ||
    raw.canMonetize === false ||
    raw.hasCommission === false ||
    raw.isDeeplinkEnabled === false ||
    statusLower === "inactive" ||
    statusLower === "disabled" ||
    statusLower === "paused" ||
    statusLower === "closed" ||
    statusLower === "rejected"
  ) {
    return { merchant: null, excludedDomains: domains };
  }

  // Strictly inspect Takeads commission fields so zero-commission merchants are NEVER suggested
  let hasPositiveCommission = false;
  let maxCommissionValue = 0;
  let explicitZeroCommission = false;
  const commissionCountriesSet = new Set<string>();
  let hasWorldwideRate = false;

  const rateArrays = [raw.commissionRates, raw.rates, raw.commissions, raw.payouts, raw.tariffs];
  let sawAnyRateArray = false;
  for (const arr of rateArrays) {
    if (!Array.isArray(arr)) continue;
    sawAnyRateArray = true;
    for (const rateObj of arr) {
      if (!rateObj || typeof rateObj !== "object") continue;
      if (rateObj.isActive === false || rateObj.active === false) continue;
      const candidates = [
        rateObj.value,
        rateObj.rate,
        rateObj.amount,
        rateObj.commission,
        rateObj.max,
        rateObj.min,
        rateObj.percent,
        rateObj.percentage,
        rateObj.payout,
      ];
      let entryVal = 0;
      for (const c of candidates) {
        const num = parseNumericCommissionValue(c);
        if (num !== null && num > entryVal) {
          entryVal = num;
        }
      }
      if (entryVal > 0) {
        hasPositiveCommission = true;
        if (entryVal > maxCommissionValue) maxCommissionValue = entryVal;
        const rateGeos = rateObj.geo ?? rateObj.countryCodes ?? rateObj.countries ?? rateObj.regions;
        if (Array.isArray(rateGeos) && rateGeos.length > 0) {
          for (const g of rateGeos) {
            const code = typeof g === "string" ? g.trim().toUpperCase() : "";
            if (code === "WW" || code === "ALL" || code === "GLOBAL" || code === "WORLDWIDE") {
              hasWorldwideRate = true;
            } else if (/^[A-Z]{2}$/.test(code)) {
              commissionCountriesSet.add(code);
            }
          }
        } else {
          hasWorldwideRate = true;
        }
      }
    }
  }

  const scalarCommissionCandidates = [
    raw.averageCommission,
    raw.avgCommission,
    raw.commission,
    raw.commissionRate,
    raw.maxCommission,
    raw.payout,
  ];
  let sawScalarCommission = false;
  for (const sc of scalarCommissionCandidates) {
    const num = parseNumericCommissionValue(sc);
    if (num !== null) {
      sawScalarCommission = true;
      if (num > 0) {
        hasPositiveCommission = true;
        if (num > maxCommissionValue) maxCommissionValue = num;
      }
    }
  }

  if ((sawAnyRateArray || sawScalarCommission) && !hasPositiveCommission) {
    explicitZeroCommission = true;
  }

  if (explicitZeroCommission) {
    return { merchant: null, excludedDomains: domains };
  }

  const primaryDomain = domains[0];
  const name = cleanApiText(raw.name || raw.merchantName || raw.title || primaryDomain, 80) || primaryDomain;
  const id = cleanApiText(raw.id ?? raw.merchantId ?? primaryDomain, 80) || primaryDomain;

  const countryCodes: string[] = [];
  const rawCountries = Array.isArray(raw.countryCodes)
    ? raw.countryCodes
    : Array.isArray(raw.countries)
      ? raw.countries
      : [];
  for (const c of rawCountries) {
    const code = typeof c === "string" ? c.trim().toUpperCase() : "";
    if (/^[A-Z]{2}$/.test(code) && !countryCodes.includes(code)) {
      countryCodes.push(code);
    }
  }

  const categories: string[] = [];
  const rawCats = Array.isArray(raw.categories)
    ? raw.categories
    : Array.isArray(raw.categoryNames)
      ? raw.categoryNames
      : [];
  for (const cat of rawCats) {
    const label =
      typeof cat === "string"
        ? cleanApiText(cat, 50)
        : cat && typeof cat === "object"
          ? cleanApiText(cat.name || cat.title || cat.slug || "", 50)
          : "";
    if (label && !categories.includes(label)) {
      categories.push(label);
    }
  }

  const description = cleanApiText(raw.description || raw.shortDescription || "", 160);
  const trackingLink = isGenuineTakeadsAffiliateLink(raw.trackingLink, primaryDomain)
    ? raw.trackingLink.trim()
    : isGenuineTakeadsAffiliateLink(raw.affiliateUrl, primaryDomain)
      ? raw.affiliateUrl.trim()
      : "";
  const isDeeplinkEnabled = raw.isDeeplinkEnabled !== false;
  const commissionCountries = hasWorldwideRate ? [] : Array.from(commissionCountriesSet);

  return {
    merchant: {
      id,
      name,
      domain: primaryDomain,
      domains,
      countryCodes,
      categories,
      description,
      trackingLink,
      isDeeplinkEnabled,
      hasVerifiedCommission: hasPositiveCommission,
      maxCommissionValue,
      commissionCountries,
      source: "merchant-api",
    },
    excludedDomains: [],
  };
}

function indexMerchantsByDomain(merchants: TakeadsMerchant[]): Map<string, TakeadsMerchant> {
  const byDomain = new Map<string, TakeadsMerchant>();
  for (const m of merchants) {
    if (!byDomain.has(m.domain)) {
      byDomain.set(m.domain, m);
    }
    for (const d of m.domains) {
      if (!byDomain.has(d)) {
        byDomain.set(d, m);
      }
    }
  }
  return byDomain;
}

// -------------------------------------------------------------------------
// Global Takeads Merchant Directory & Redirect Health Cache
// -------------------------------------------------------------------------

interface VerifiedProbeCache {
  expiresAt: number;
  byDomain: Map<string, { candidate: CandidateStore; trackingLink: string }>;
}

interface GlobalMerchantDirectory {
  expiresAt: number;
  syncedPages: number;
  isComplete: boolean;
  byDomain: Map<string, TakeadsMerchant>;
  byCountry: Map<string, TakeadsMerchant[]>;
  globalMerchants: TakeadsMerchant[];
  excludedNonCommissionDomains: Set<string>;
}

let probeCache: VerifiedProbeCache | null = null;
let probeInFlight: Promise<{ ok: boolean; authError?: boolean }> | null = null;
// Caches live PUT /v2/resolve monetization checks per domain for this publisher's Public Key
const resolveMonetizationCache = new Map<string, { monetizable: boolean; expiresAt: number }>();

function getCachedResolveMonetization(domain: string): boolean | null {
  const norm = normalizeDomain(domain);
  if (!norm) return null;
  const entry = resolveMonetizationCache.get(norm);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    resolveMonetizationCache.delete(norm);
    return null;
  }
  return entry.monetizable;
}

function setCachedResolveMonetization(domain: string, monetizable: boolean): void {
  const norm = normalizeDomain(domain);
  if (!norm) return;
  resolveMonetizationCache.set(norm, {
    monetizable,
    expiresAt: Date.now() + TAKEADS_CATALOG_TTL_MS,
  });
}

let globalDirectory: GlobalMerchantDirectory = {
  expiresAt: 0,
  syncedPages: 0,
  isComplete: false,
  byDomain: new Map(),
  byCountry: new Map(),
  globalMerchants: [],
  excludedNonCommissionDomains: new Set(),
};
let directorySyncInFlight: Promise<void> | null = null;
let merchantApiUnavailableUntil = 0;
let couponsApiUnavailableUntil = 0;

function addMerchantToGlobalDirectory(dir: GlobalMerchantDirectory, merchant: TakeadsMerchant): void {
  if (dir.byDomain.has(merchant.domain)) return;
  dir.byDomain.set(merchant.domain, merchant);
  for (const d of merchant.domains) {
    if (!dir.byDomain.has(d)) {
      dir.byDomain.set(d, merchant);
    }
  }
  if (merchant.countryCodes.length === 0) {
    dir.globalMerchants.push(merchant);
  } else {
    for (const cc of merchant.countryCodes) {
      let arr = dir.byCountry.get(cc);
      if (!arr) {
        arr = [];
        dir.byCountry.set(cc, arr);
      }
      arr.push(merchant);
    }
  }
}

async function fetchMerchantsPageFromApi(
  nextCursor: string | null,
  signal?: AbortSignal
): Promise<{
  ok: boolean;
  status: number;
  merchants: TakeadsMerchant[];
  excludedDomains: string[];
  next: string | null;
}> {
  const publicKey = getTakeadsPublicKey();
  if (!publicKey) return { ok: false, status: 0, merchants: [], excludedDomains: [], next: null };

  const params = new URLSearchParams();
  params.set("limit", "500");
  params.set("isActive", "true");
  if (nextCursor) {
    params.set("next", nextCursor);
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), TAKEADS_REQUEST_TIMEOUT_MS);
  const onParentAbort = () => controller.abort();
  signal?.addEventListener("abort", onParentAbort, { once: true });

  try {
    const response = await fetch(`${TAKEADS_MERCHANT_ENDPOINT}?${params.toString()}`, {
      method: "GET",
      redirect: "error",
      headers: {
        Authorization: `Bearer ${publicKey}`,
        Accept: "application/json",
      },
      signal: controller.signal,
    });

    if (!response.ok) {
      return { ok: false, status: response.status, merchants: [], excludedDomains: [], next: null };
    }

    const payload: any = await response.json();
    const rawList = Array.isArray(payload?.data)
      ? payload.data
      : Array.isArray(payload?.merchants)
        ? payload.merchants
        : Array.isArray(payload?.items)
          ? payload.items
          : [];

    const merchants: TakeadsMerchant[] = [];
    const excludedDomains: string[] = [];
    for (const item of rawList) {
      const parsed = parseMerchantObject(item);
      if (parsed.merchant) {
        merchants.push(parsed.merchant);
      } else if (parsed.excludedDomains.length > 0) {
        excludedDomains.push(...parsed.excludedDomains);
      }
    }

    const rawNext = payload?.meta?.next ?? payload?.next ?? null;
    const next = typeof rawNext === "string" && rawNext.trim() ? rawNext.trim() : null;

    return { ok: true, status: response.status, merchants, excludedDomains, next };
  } catch (err: any) {
    if (!signal?.aborted) {
      console.warn("[Takeads] Merchant API fetch failed:", err?.message || err);
    }
    return { ok: false, status: 0, merchants: [], excludedDomains: [], next: null };
  } finally {
    clearTimeout(timeoutId);
    signal?.removeEventListener("abort", onParentAbort);
  }
}

function triggerBackgroundDirectorySync(): Promise<void> {
  const now = Date.now();
  if (!isTakeadsConfigured() || now < merchantApiUnavailableUntil) {
    return Promise.resolve();
  }
  if (globalDirectory.isComplete && now < globalDirectory.expiresAt) {
    return Promise.resolve();
  }
  if (directorySyncInFlight) {
    return directorySyncInFlight;
  }

  directorySyncInFlight = (async () => {
    const freshDir: GlobalMerchantDirectory =
      globalDirectory.syncedPages > 0 && now < globalDirectory.expiresAt
        ? globalDirectory
        : {
            expiresAt: now + TAKEADS_CATALOG_TTL_MS,
            syncedPages: 0,
            isComplete: false,
            byDomain: new Map(),
            byCountry: new Map(),
            globalMerchants: [],
            excludedNonCommissionDomains: new Set(),
          };

    let cursor: string | null = null;
    let totalAdded = 0;

    for (let page = 0; page < TAKEADS_MAX_MERCHANT_SYNC_PAGES; page++) {
      const res = await fetchMerchantsPageFromApi(cursor);
      if (!res.ok) {
        if (res.status === 401 || res.status === 403 || res.status === 404) {
          merchantApiUnavailableUntil = Date.now() + 15 * 60 * 1000;
        }
        break;
      }

      for (const excludedDom of res.excludedDomains) {
        freshDir.excludedNonCommissionDomains.add(excludedDom);
      }
      for (const m of res.merchants) {
        freshDir.excludedNonCommissionDomains.delete(m.domain);
        addMerchantToGlobalDirectory(freshDir, m);
        totalAdded++;
      }
      freshDir.syncedPages = page + 1;
      freshDir.expiresAt = Date.now() + TAKEADS_CATALOG_TTL_MS;
      globalDirectory = freshDir;

      if (!res.next || (res.merchants.length === 0 && res.excludedDomains.length === 0)) {
        freshDir.isComplete = true;
        break;
      }
      cursor = res.next;
    }

    if (totalAdded > 0) {
      console.log(
        `[Takeads] Synced ${freshDir.byDomain.size} unique active commission merchants across ${freshDir.byCountry.size} countries (excluded ${freshDir.excludedNonCommissionDomains.size} non-commission/inactive domains).`
      );
    }
  })().finally(() => {
    directorySyncInFlight = null;
  });

  return directorySyncInFlight;
}

// Tracks domains & brand families whose live affiliate redirect is verified as broken/dead
const brokenTakeadsDomains = new Map<string, number>();
const brokenBrandFamilies = new Map<string, number>();
const domainHealthCache = new Map<string, { healthy: boolean; expiresAt: number }>();

function isBrokenTakeadsDomain(domain: string): boolean {
  const norm = normalizeDomain(domain);
  if (!norm) return false;
  const now = Date.now();
  const exp = brokenTakeadsDomains.get(norm);
  if (exp) {
    if (now > exp) {
      brokenTakeadsDomains.delete(norm);
    } else {
      return true;
    }
  }
  const brand = extractBrandRootLabel(norm);
  if (brand) {
    const brandExp = brokenBrandFamilies.get(brand);
    if (brandExp) {
      if (now > brandExp) {
        brokenBrandFamilies.delete(brand);
      } else {
        return true;
      }
    }
  }
  return false;
}

function markBrokenTakeadsDomain(domain: string, blockBrandFamily: boolean = false): void {
  const norm = normalizeDomain(domain);
  if (!norm) return;
  const exp = Date.now() + TAKEADS_CATALOG_TTL_MS;
  brokenTakeadsDomains.set(norm, exp);
  domainHealthCache.set(norm, { healthy: false, expiresAt: exp });
  if (blockBrandFamily) {
    const brand = extractBrandRootLabel(norm);
    if (brand && brand.length >= 3) {
      brokenBrandFamilies.set(brand, exp);
    }
  }
}

function getCachedDomainHealth(domain: string): boolean | null {
  const norm = normalizeDomain(domain);
  if (!norm) return null;
  if (isBrokenTakeadsDomain(norm)) return false;
  const cached = domainHealthCache.get(norm);
  if (!cached) return null;
  if (Date.now() > cached.expiresAt) {
    domainHealthCache.delete(norm);
    return null;
  }
  return cached.healthy;
}

function isKnownBrokenCampaignUrl(urlLower: string): boolean {
  return (
    urlLower.includes("onelink.shein.com") ||
    (urlLower.includes("thevospad.com") && urlLower.includes("onelink.")) ||
    urlLower.includes("i.gtxen.com") ||
    urlLower.includes("kuiper/un1.html") ||
    urlLower.includes("/ark/default") ||
    urlLower.includes("campaign_expired") ||
    urlLower.includes("campaign_paused") ||
    urlLower.includes("offer_inactive") ||
    urlLower.includes("offer_disabled") ||
    urlLower.includes("offer_not_found") ||
    urlLower.includes("no_active_offer") ||
    urlLower.includes("advertiser_disabled") ||
    urlLower.includes("program_closed") ||
    urlLower.includes("inactive_campaign") ||
    urlLower.includes("targeting_failed") ||
    urlLower.includes("tatrck.com/error")
  );
}

function isBannerOnlyNonDeeplinkUrl(urlString: string): boolean {
  try {
    const u = new URL(urlString);
    const host = u.hostname.toLowerCase();
    const path = u.pathname.toLowerCase();
    // Known banner-only affiliate click endpoints that drop deep-link search URLs
    if (host.endsWith("chinesean.com") && path.includes("/affiliate/clickbanner.do")) {
      const hasTargetParam = ["url", "dest", "target", "ulp", "ued", "u", "murl", "deeplink"].some(
        (k) => (u.searchParams.get(k) || "").trim().startsWith("http")
      );
      if (!hasTargetParam) return true;
    }
    return false;
  } catch {
    return false;
  }
}

const STRONG_SEARCH_QUERY_PARAM_KEYS = new Set([
  "q", "k", "keyword", "keywords", "search", "query", "text", "st", "kw",
  "searchtext", "searchkey", "searchterm", "searchvalue", "stext", "_nkw",
  "d", "term", "search_key", "freetext", "ntt", "qs", "search_query", "sk",
]);

const WEAK_SEARCH_QUERY_PARAM_KEYS = new Set(["s", "p", "w"]);

const SEARCH_PATH_INDICATOR_RE =
  /\/(?:search|catalogsearch|aisearch|sitesearch|pdsearch|search-results|search_result|searchresult|searchresults|wholesale-|wholesale\/search|sch\/|sr(?:\/|$)|suche\/|katalog\/|list\.html|ara(?:\/|$)|c\/search|p\/pl|keyword\.php|featured\/|shopping\/search|shop\/search|mens\/search|s\/[^/]+|w$)/i;

export function isBareStoreHomepageUrl(urlString: string): boolean {
  try {
    const parsed = new URL(urlString);
    for (const [key, val] of parsed.searchParams.entries()) {
      const kl = key.toLowerCase();
      const vt = val.trim();
      if (STRONG_SEARCH_QUERY_PARAM_KEYS.has(kl) && vt.length > 0) {
        return false;
      }
      if (WEAK_SEARCH_QUERY_PARAM_KEYS.has(kl) && /[a-zA-Z\u0600-\u06FF]{2,}/.test(vt) && !/^[0-9a-f]{12,}$/i.test(vt)) {
        return false;
      }
    }
    const cleanPath = (parsed.pathname || "/").replace(/\/+$/, "").toLowerCase();
    if (!cleanPath || cleanPath === "") return true;
    // Affiliate landing homepages like offer.alibaba.com/cps/<id> with no search query
    if (/^\/cps\/[a-z0-9_-]+$/i.test(cleanPath)) return true;
    // Pure home/welcome/store/locale/region prefix with no search path (e.g. /uk, /hk/en, /en-sa, /sa/en, /us/en/home, /default.aspx)
    if (
      /^\/(?:home|homepage|welcome|store|shop|index(?:\.[a-z0-9]+)?|default(?:\.[a-z0-9]+)?|(?:[a-z]{2}(?:[-_][a-z]{2})?|(?:saudi|uae|egypt|qatar|kuwait|oman|bahrain|usa|uk|global|intl?|international)(?:[-_](?:ar|en))?)(?:\/(?:[a-z]{2}(?:[-_][a-z]{2})?|shop|store|home|homepage|welcome|index(?:\.[a-z0-9]+)?|default(?:\.[a-z0-9]+)?)){0,2})$/.test(
        cleanPath
      )
    ) {
      return true;
    }
    return false;
  } catch {
    return true;
  }
}

function extractProbeSearchKeyword(probeUrl?: string): string {
  if (!probeUrl) return "";
  try {
    const u = new URL(probeUrl);
    for (const [k, v] of u.searchParams.entries()) {
      const kl = k.toLowerCase();
      if (STRONG_SEARCH_QUERY_PARAM_KEYS.has(kl)) {
        const word = v.trim().toLowerCase().split(/[\s+-]+/).find((w) => w.length >= 3);
        if (word) return word;
      }
    }
    const decodedPath = decodeURIComponent(u.pathname || "").toLowerCase();
    const pathMatch =
      decodedPath.match(/wholesale-([a-z0-9]{3,})/i) ||
      decodedPath.match(/\/(?:search|pdsearch|suche|featured|s)\/([a-z0-9]{3,})/i);
    if (pathMatch?.[1]) return pathMatch[1].toLowerCase();
    return "";
  } catch {
    return "";
  }
}

function unwrapMerchantBlockedUrl(urlString: string): string {
  try {
    const u = new URL(urlString);
    const p = u.pathname.toLowerCase();
    if (p === "/blocked" || p === "/captcha" || p.startsWith("/blocked/")) {
      const rawTarget = (u.searchParams.get("url") || u.searchParams.get("redirect") || "").trim();
      if (rawTarget) {
        let decoded = rawTarget;
        if (/^[A-Za-z0-9+/_=-]{8,}$/.test(rawTarget) && !rawTarget.startsWith("/") && !rawTarget.startsWith("http")) {
          try {
            const b64 = Buffer.from(rawTarget.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf-8");
            if (b64.startsWith("/") || b64.startsWith("http")) decoded = b64;
          } catch {
            // keep rawTarget
          }
        }
        return new URL(decoded, u.origin).toString();
      }
    }
    return urlString;
  } catch {
    return urlString;
  }
}

function preservesSearchDestination(urlString: string, probeKeyword: string): boolean {
  try {
    const u = new URL(urlString);
    const host = u.hostname.toLowerCase();
    const path = u.pathname || "/";
    if (host.startsWith("listado.") && path.length > 2) return true;
    if (SEARCH_PATH_INDICATOR_RE.test(path)) return true;

    for (const [k, v] of u.searchParams.entries()) {
      const kl = k.toLowerCase();
      const vt = v.trim();
      if (STRONG_SEARCH_QUERY_PARAM_KEYS.has(kl) && vt.length > 0) return true;
      if (WEAK_SEARCH_QUERY_PARAM_KEYS.has(kl) && probeKeyword && vt.toLowerCase().includes(probeKeyword)) return true;
    }

    if (probeKeyword && probeKeyword.length >= 3) {
      const decodedPath = decodeURIComponent(path).toLowerCase();
      if (decodedPath.includes(probeKeyword)) return true;
      for (const [k, v] of u.searchParams.entries()) {
        const kl = k.toLowerCase();
        if (
          kl.startsWith("utm_") ||
          kl.includes("click") ||
          kl.includes("subid") ||
          kl.includes("aff") ||
          kl.includes("ref") ||
          kl === "dp" ||
          kl === "cv" ||
          kl === "pid"
        ) {
          continue;
        }
        if (v.toLowerCase().includes(probeKeyword)) return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}

function extractHtmlRedirectUrl(html: string, baseUrl: string, allowJsRedirect: boolean): string | null {
  if (!html) return null;
  const decodeHtmlAttr = (raw: string): string =>
    raw
      .replace(/&amp;/gi, "&")
      .replace(/&#x2f;/gi, "/")
      .replace(/&#47;/gi, "/")
      .trim();

  // Match <meta http-equiv="refresh" content="0;URL=..."> carefully so embedded url= query params are preserved
  const metaTagRe = /<meta\b[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*>/gi;
  let tagMatch: RegExpExecArray | null;
  while ((tagMatch = metaTagRe.exec(html)) !== null) {
    const tag = tagMatch[0];
    const contentMatch =
      tag.match(/\bcontent\s*=\s*"([^"]+)"/i) ||
      tag.match(/\bcontent\s*=\s*'([^']+)'/i);
    if (contentMatch?.[1]) {
      const urlPart = contentMatch[1].match(/^\s*\d*\s*;\s*url\s*=\s*(.+)$/i);
      if (urlPart?.[1]) {
        const cleaned = decodeHtmlAttr(urlPart[1]).replace(/^['"]|['"]$/g, "").trim();
        if (cleaned) {
          try {
            return new URL(cleaned, baseUrl).toString();
          } catch {
            // ignore invalid URL
          }
        }
      }
    }
  }

  if (allowJsRedirect) {
    const jsPatterns = [
      /(?:window|self|top|document)\.location(?:\.href)?\s*=\s*["'](https?:\/\/[^"'\s<>]+)["']/i,
      /\blocation\.(?:replace|assign)\(\s*["'](https?:\/\/[^"'\s<>]+)["']\s*\)/i,
    ];
    for (const re of jsPatterns) {
      const m = html.match(re);
      if (m?.[1]) {
        const cleaned = decodeHtmlAttr(m[1].replace(/\\u002[fF]/g, "/").replace(/\\\//g, "/"));
        try {
          return new URL(cleaned, baseUrl).toString();
        } catch {
          // ignore
        }
      }
    }
  }
  return null;
}

function hasAffiliateTrackingParams(urlObj: URL): boolean {
  const full = urlObj.search.toLowerCase();
  return /(?:^|[?&])(?:tag|aff_id|affid|af|aff|admitad_uid|clickid|irclickid|irgwc|clickref|subid|sub_id|pubid|pub_id|partner|awinaffid|ranmid|cjevent|campaign_id|offer_id|pid|wid|cid|utm_campaign|utm_medium=affiliate|utm_source=(?:admitad|takeads|skimlinks|viglink|impact|cj|awin|rakuten|partner|affiliate)|f=bm(?:%7c|\|)aff)=?/i.test(
    full
  );
}

/**
 * Strict multi-hop SSRF-safe affiliate link & deep-link health verification:
 * - Verifies hop-0 tracking link and rejects unmonetized raw pass-through redirects (zero commission!).
 * - Decodes `deeplink=` target, rejects banner-only non-deeplink redirectors and broken/expired/geo-blocked campaigns.
 * - Follows HTTP 3xx, `<meta http-equiv="refresh">`, and intermediate tracker JS redirects up to 9 hops (SSRF checked on every hop).
 * - Requires the chain to actually reach the target merchant domain (never fails open on stuck intermediate trackers or `TARGETING_FAILED`).
 * - Rejects campaigns that strip deep links and dump users onto a bare/locale store homepage or affiliate splash page.
 * - Rejects 404/410/5xx on ANY hop, soft-404 titles on merchant pages, and 4xx/Cloudflare challenges on intermediate trackers.
 * - Allows bot-WAF 403/429 ONLY once the chain has successfully landed on a search-preserving URL of the target merchant domain.
 */
async function verifyTakeadsRedirectHealth(
  trackingLink: string,
  domain: string,
  signal?: AbortSignal,
  expectedProbeUrl?: string
): Promise<boolean> {
  const normDom = normalizeDomain(domain);
  const cached = getCachedDomainHealth(normDom);
  if (cached !== null) return cached;

  if (!isValidHttpsUrl(trackingLink)) {
    markBrokenTakeadsDomain(normDom, false);
    return false;
  }

  const probeKeyword = extractProbeSearchKeyword(expectedProbeUrl);
  const expectsSearchDestination = Boolean(expectedProbeUrl && !isBareStoreHomepageUrl(expectedProbeUrl));

  let currentUrl = trackingLink;
  let reachedTargetStore = false;
  let targetUrlVerified = false;
  const deadline = Date.now() + 9000;

  for (let hop = 0; hop < 9; hop++) {
    if (signal?.aborted) return reachedTargetStore && targetUrlVerified;
    if (!isSafePublicHttpUrl(currentUrl)) {
      markBrokenTakeadsDomain(normDom, false);
      return false;
    }

    if (isBannerOnlyNonDeeplinkUrl(currentUrl)) {
      console.warn(`[Takeads] Skipping '${normDom}' because affiliate tracker (${currentUrl.slice(0, 90)}) drops deep links (banner-only).`);
      markBrokenTakeadsDomain(normDom, false);
      return false;
    }

    const parsedCurrent = new URL(currentUrl);
    const currentHost = parsedCurrent.hostname;

    // Fast-unwrap tatrck.com/v1/go/?deeplink=... without an extra round-trip
    if (currentHost.toLowerCase().endsWith("tatrck.com") && parsedCurrent.pathname.toLowerCase().startsWith("/v1/go")) {
      const dl = parsedCurrent.searchParams.get("deeplink") || "";
      if (dl && isSafePublicHttpUrl(dl)) {
        if (isKnownBrokenCampaignUrl(dl.toLowerCase())) {
          console.warn(`[Takeads] Skipping '${normDom}' because tatrck deeplink points to broken campaign.`);
          markBrokenTakeadsDomain(normDom, true);
          return false;
        }
        currentUrl = dl;
        continue;
      }
    }

    const isTargetStore = hostMatchesMerchantDomain(currentHost, normDom);
    if (isTargetStore) {
      reachedTargetStore = true;
      const effectiveUrl = unwrapMerchantBlockedUrl(currentUrl);
      if (isBareStoreHomepageUrl(effectiveUrl)) {
        console.warn(`[Takeads] Skipping '${normDom}' because redirect landed on store homepage (${effectiveUrl}) instead of search results.`);
        markBrokenTakeadsDomain(normDom, false);
        return false;
      }
      if (expectsSearchDestination && !preservesSearchDestination(effectiveUrl, probeKeyword)) {
        console.warn(`[Takeads] Skipping '${normDom}' because affiliate redirect stripped the search query (${effectiveUrl}).`);
        markBrokenTakeadsDomain(normDom, false);
        return false;
      }
      targetUrlVerified = true;
    }

    const remainingMs = deadline - Date.now();
    if (remainingMs <= 350) {
      if (reachedTargetStore && targetUrlVerified) {
        domainHealthCache.set(normDom, { healthy: true, expiresAt: Date.now() + TAKEADS_CATALOG_TTL_MS });
        return true;
      }
      console.warn(`[Takeads] Skipping '${normDom}' because redirect verification timed out before reaching a verified store search page.`);
      return false;
    }

    const validatedHop = await resolvePublicUrlWithDns(currentUrl, true);
    if (!validatedHop) {
      markBrokenTakeadsDomain(normDom, false);
      return false;
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), Math.min(3500, remainingMs));
    const onParentAbort = () => controller.abort();
    signal?.addEventListener("abort", onParentAbort, { once: true });

    try {
      const resp = await pinnedSingleHopGet(validatedHop, controller.signal, {
        maxBytes: 16384,
        referer: "https://pezeex.com/",
        acceptAnyText: true,
      });

      const status = resp.statusCode;

      // Hard failures (404, 410, 5xx) on ANY hop (tracker OR final store page) => broken link
      if (status === 404 || status === 410 || status >= 500) {
        console.warn(`[Takeads] Skipping '${normDom}' because hop ${hop} (${currentHost}) returned HTTP ${status}.`);
        markBrokenTakeadsDomain(normDom, false);
        return false;
      }

      // 400-403 / 429: valid WAF challenge ONLY on a verified search-preserving target store page; broken if on an intermediate affiliate tracker
      if (status >= 400) {
        if (isTargetStore && targetUrlVerified && (status === 403 || status === 429 || status === 418)) {
          domainHealthCache.set(normDom, { healthy: true, expiresAt: Date.now() + TAKEADS_CATALOG_TTL_MS });
          return true;
        }
        console.warn(`[Takeads] Skipping '${normDom}' because redirector hop ${hop} (${currentHost}) returned HTTP ${status}.`);
        markBrokenTakeadsDomain(normDom, false);
        return false;
      }

      // 3xx redirect
      if (status >= 300 && status < 400) {
        const loc = resp.location || "";
        if (!loc) {
          if (reachedTargetStore && targetUrlVerified) {
            domainHealthCache.set(normDom, { healthy: true, expiresAt: Date.now() + TAKEADS_CATALOG_TTL_MS });
            return true;
          }
          markBrokenTakeadsDomain(normDom, false);
          return false;
        }

        const resolvedNext = new URL(loc, currentUrl);
        const deeplinkParam = hop === 0 ? resolvedNext.searchParams.get("deeplink") : null;

        // STRICT COMMISSION PASS-THROUGH CHECK on hop 0
        if (
          hop === 0 &&
          !deeplinkParam &&
          hostMatchesMerchantDomain(resolvedNext.hostname, normDom) &&
          !hasAffiliateTrackingParams(resolvedNext)
        ) {
          console.warn(`[Takeads] Skipping '${normDom}' because hop 0 returned an unmonetized raw pass-through (${resolvedNext.toString()}) with no affiliate commission tracking.`);
          markBrokenTakeadsDomain(normDom, false);
          return false;
        }

        const candidateNext = deeplinkParam && isSafePublicHttpUrl(deeplinkParam)
          ? deeplinkParam
          : resolvedNext.toString();

        const checkStr = `${resolvedNext.toString()} ${deeplinkParam || ""}`.toLowerCase();
        if (isKnownBrokenCampaignUrl(checkStr)) {
          console.warn(`[Takeads] Skipping '${normDom}' because its affiliate redirect resolves to a broken/non-working campaign.`);
          markBrokenTakeadsDomain(normDom, true);
          return false;
        }

        currentUrl = candidateNext;
        continue;
      }

      // 2xx final page or HTML/JS affiliate redirector (already capped to 16KB inside pinnedSingleHopGet)
      const snippet = resp.html || "";

      const lowerSnip = snippet.toLowerCase();

      // Reject explicit dead-campaign / geo-targeting error bodies immediately
      if (
        lowerSnip.includes("targeting_failed") ||
        lowerSnip.includes("offer_not_found") ||
        lowerSnip.includes("campaign_paused") ||
        lowerSnip.includes("campaign has expired") ||
        lowerSnip.includes("offer has expired") ||
        lowerSnip.includes("offer is no longer active") ||
        lowerSnip.includes("link is no longer valid") ||
        lowerSnip.includes("invalid_click") ||
        lowerSnip.includes("geo_blocked") ||
        lowerSnip.includes("blocked_country")
      ) {
        console.warn(`[Takeads] Skipping '${normDom}' because hop ${hop} (${currentHost}) returned dead-campaign/targeting failure.`);
        markBrokenTakeadsDomain(normDom, false);
        return false;
      }

      // Follow HTML <meta refresh> or intermediate tracker JS redirects (SSRF-checked)
      const allowJs = !isTargetStore || snippet.length < 2500;
      const htmlNext = extractHtmlRedirectUrl(snippet, currentUrl, allowJs);
      if (htmlNext && htmlNext !== currentUrl && isSafePublicHttpUrl(htmlNext)) {
        if (isKnownBrokenCampaignUrl(htmlNext.toLowerCase())) {
          markBrokenTakeadsDomain(normDom, true);
          return false;
        }
        currentUrl = htmlNext;
        continue;
      }

      if (!isTargetStore) {
        // Dead end on an intermediate affiliate tracker (e.g., Cloudflare challenge on fatcoupon.com, error stub, etc.)
        console.warn(`[Takeads] Skipping '${normDom}' because affiliate chain stopped on intermediate tracker (${currentHost}) without reaching store.`);
        markBrokenTakeadsDomain(normDom, false);
        return false;
      }

      // Final merchant page: reject soft-404 titles
      const titleMatch = snippet.match(/<title[^>]*>([\s\S]{1,140}?)<\/title>/i);
      const titleText = (titleMatch?.[1] || "").toLowerCase();
      if (
        /\b404\b/.test(titleText) ||
        titleText.includes("page not found") ||
        titleText.includes("صفحة غير موجودة") ||
        titleText.includes("الصفحة غير موجودة")
      ) {
        console.warn(`[Takeads] Skipping '${normDom}' because merchant destination returned soft-404 title.`);
        markBrokenTakeadsDomain(normDom, false);
        return false;
      }

      domainHealthCache.set(normDom, { healthy: true, expiresAt: Date.now() + TAKEADS_CATALOG_TTL_MS });
      return true;
    } catch (err: any) {
      if (signal?.aborted) return reachedTargetStore && targetUrlVerified;
      const errName = String(err?.name || "");
      const errCode = String(err?.cause?.code || err?.code || "");
      const isAbort = errName === "AbortError";

      if (!isAbort) {
        if (
          errCode === "ENOTFOUND" ||
          errCode === "EAI_AGAIN" ||
          errCode === "ECONNREFUSED" ||
          errCode.startsWith("ERR_TLS") ||
          errCode.startsWith("CERT_")
        ) {
          console.warn(`[Takeads] Skipping '${normDom}' due to network/DNS error (${errCode}) at ${currentHost}.`);
          markBrokenTakeadsDomain(normDom, false);
          return false;
        }
      }
      if (reachedTargetStore && targetUrlVerified) {
        domainHealthCache.set(normDom, { healthy: true, expiresAt: Date.now() + TAKEADS_CATALOG_TTL_MS });
        return true;
      }
      return false;
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onParentAbort);
    }
  }

  if (reachedTargetStore && targetUrlVerified) {
    domainHealthCache.set(normDom, { healthy: true, expiresAt: Date.now() + TAKEADS_CATALOG_TTL_MS });
    return true;
  }
  console.warn(`[Takeads] Skipping '${normDom}' because redirect chain exceeded max hops without reaching a verified store search page.`);
  markBrokenTakeadsDomain(normDom, false);
  return false;
}

async function ensureVerifiedProbeCache(signal?: AbortSignal): Promise<{ ok: boolean; authError?: boolean }> {
  const now = Date.now();
  if (probeCache && now < probeCache.expiresAt && probeCache.byDomain.size > 0) {
    return { ok: true };
  }
  if (probeInFlight) {
    return probeInFlight;
  }

  probeInFlight = (async () => {
    const probeUrls = CANDIDATE_STORES.map((s) => s.probeUrl);
    const res = await resolveTakeadsUrls(probeUrls, signal);
    if (res.authError) {
      return { ok: false, authError: true };
    }
    if (!res.ok) {
      return { ok: Boolean(probeCache && probeCache.byDomain.size > 0) };
    }

    const resolvedCandidates: Array<{ candidate: CandidateStore; dom: string; trackingLink: string }> = [];
    for (const candidate of CANDIDATE_STORES) {
      const tracking = res.linksByIri.get(candidate.probeUrl);
      if (tracking) {
        const dom = normalizeDomain(candidate.domain);
        if (dom) {
          resolvedCandidates.push({ candidate, dom, trackingLink: tracking });
        }
      }
    }

    // Verify affiliate redirect chains in parallel once per 6h cache window
    const healthChecks = await Promise.all(
      resolvedCandidates.map(async (entry) => {
        const healthy = await verifyTakeadsRedirectHealth(
          entry.trackingLink,
          entry.dom,
          signal,
          entry.candidate.probeUrl
        );
        return { ...entry, healthy };
      })
    );

    const map = new Map<string, { candidate: CandidateStore; trackingLink: string }>();
    for (const entry of healthChecks) {
      if (!entry.healthy) {
        continue;
      }
      map.set(entry.dom, { candidate: entry.candidate, trackingLink: entry.trackingLink });
      setCachedResolveMonetization(entry.dom, true);
    }

    if (map.size > 0) {
      probeCache = {
        expiresAt: Date.now() + TAKEADS_CATALOG_TTL_MS,
        byDomain: map,
      };
      console.log(`[Takeads] Verified ${map.size} healthy major retail merchants via live /v2/resolve.`);
      return { ok: true };
    }
    return { ok: false };
  })().finally(() => {
    probeInFlight = null;
  });

  return probeInFlight;
}

const CCTLD_ALLOWED_COUNTRIES: Record<string, string[]> = {
  de: ["DE", "AT", "CH"],
  fr: ["FR", "BE", "CH", "LU"],
  it: ["IT", "CH"],
  es: ["ES"],
  nl: ["NL", "BE"],
  pl: ["PL"],
  se: ["SE"],
  dk: ["DK"],
  no: ["NO"],
  fi: ["FI"],
  cz: ["CZ"],
  at: ["AT", "DE"],
  ch: ["CH"],
  be: ["BE", "NL", "FR"],
  pt: ["PT"],
  gr: ["GR"],
  hu: ["HU"],
  ro: ["RO"],
  ru: ["RU"],
  ua: ["UA"],
  uk: ["GB", "IE"],
  ca: ["CA"],
  au: ["AU", "NZ"],
  nz: ["NZ", "AU"],
  jp: ["JP"],
  in: ["IN"],
  br: ["BR"],
  mx: ["MX"],
  sa: ["SA"],
  ae: ["AE"],
  eg: ["EG"],
  tr: ["TR"],
  kr: ["KR"],
  cn: ["CN"],
  tw: ["TW"],
  sg: ["SG"],
  my: ["MY"],
  id: ["ID"],
  th: ["TH"],
  vn: ["VN"],
  za: ["ZA"],
};

function isForeignCountrySpecificMerchant(merchant: TakeadsMerchant, targetCountryCode: string): boolean {
  const cc = (targetCountryCode || "US").toUpperCase();
  const dom = merchant.domain.toLowerCase();
  const parts = dom.split(".");
  const tld = parts[parts.length - 1] || "";
  if (tld && CCTLD_ALLOWED_COUNTRIES[tld]) {
    if (!CCTLD_ALLOWED_COUNTRIES[tld].includes(cc)) {
      return true;
    }
  }
  const nameCountryMatch = merchant.name.trim().match(/\s+(DE|FR|IT|ES|NL|PL|SE|DK|NO|FI|CZ|AT|CH|BE|PT|GR|HU|RO|RU|UA|UK|GB|CA|AU|NZ|JP|IN|BR|MX|US|TR|KR)$/);
  if (nameCountryMatch) {
    const suffix = nameCountryMatch[1] === "UK" ? "GB" : nameCountryMatch[1];
    if (suffix !== cc) {
      return true;
    }
  }
  return false;
}

/**
 * Returns strictly country-eligible, healthy Takeads merchants for `countryCode`.
 */
async function getVerifiedTakeadsMerchantsForCountry(
  countryCode: string,
  signal?: AbortSignal
): Promise<{ merchants: TakeadsMerchant[]; byDomain: Map<string, TakeadsMerchant>; authError?: boolean }> {
  const cc = (countryCode || "US").toUpperCase();
  const region = getRegionForCountry(cc);

  const syncPromise = triggerBackgroundDirectorySync();
  const probePromise = ensureVerifiedProbeCache(signal);

  const [probeRes] = await Promise.all([
    probePromise,
    Promise.race([syncPromise, new Promise<void>((resolve) => setTimeout(resolve, 2200))]),
  ]);

  if (probeRes.authError && globalDirectory.byDomain.size === 0) {
    return { merchants: [], byDomain: new Map(), authError: true };
  }

  const merged = new Map<string, TakeadsMerchant>();
  const isMerchantCommissionEligibleForCountry = (m: TakeadsMerchant): boolean => {
    if (globalDirectory.excludedNonCommissionDomains.has(m.domain)) return false;
    if (getCachedResolveMonetization(m.domain) === false) return false;
    if (m.commissionCountries.length > 0 && !m.commissionCountries.includes(cc)) return false;
    return true;
  };

  // 1. Add strictly country-matched, commission-eligible merchants from live Takeads /v2/merchant API
  const countryApiMerchants = globalDirectory.byCountry.get(cc) || [];
  for (const m of countryApiMerchants) {
    if (isBrokenTakeadsDomain(m.domain) || isForeignCountrySpecificMerchant(m, cc)) continue;
    if (!isMerchantCommissionEligibleForCountry(m)) continue;
    merged.set(m.domain, m);
  }

  // 2. Add live /v2/resolve verified commission merchants eligible for this country/region
  // Cross-checked against /v2/merchant so we NEVER override Takeads's real geo/commission exclusions!
  if (probeCache) {
    for (const [dom, entry] of probeCache.byDomain.entries()) {
      if (isBrokenTakeadsDomain(dom)) continue;
      if (globalDirectory.excludedNonCommissionDomains.has(dom)) continue;
      if (getCachedResolveMonetization(dom) === false) continue;

      const c = entry.candidate;
      if (!c.regions.includes(region) && !c.regions.includes("GLOBAL")) {
        continue;
      }

      const apiRecord = globalDirectory.byDomain.get(dom);
      if (apiRecord) {
        if (apiRecord.countryCodes.length > 0 && !apiRecord.countryCodes.includes(cc)) {
          continue;
        }
        if (apiRecord.commissionCountries.length > 0 && !apiRecord.commissionCountries.includes(cc)) {
          continue;
        }
      }

      const existing = merged.get(dom);
      if (existing) {
        merged.set(dom, {
          ...existing,
          // Preserve our curated precise vertical tags alongside API categories
          categories: Array.from(new Set([...c.categories, ...existing.categories])),
          trackingLink: existing.trackingLink || entry.trackingLink,
          hasVerifiedCommission: true,
        });
      } else {
        merged.set(dom, {
          id: apiRecord?.id || dom,
          name: c.name,
          domain: dom,
          domains: apiRecord?.domains?.length ? apiRecord.domains : [dom],
          countryCodes: apiRecord?.countryCodes?.length ? apiRecord.countryCodes : (c.regions.includes(region) ? [cc] : []),
          categories: apiRecord?.categories?.length ? Array.from(new Set([...c.categories, ...apiRecord.categories])) : c.categories,
          description: c.categories.join(", "),
          trackingLink: apiRecord?.trackingLink || entry.trackingLink,
          isDeeplinkEnabled: apiRecord ? apiRecord.isDeeplinkEnabled : true,
          hasVerifiedCommission: true,
          maxCommissionValue: apiRecord?.maxCommissionValue || 0,
          commissionCountries: apiRecord?.commissionCountries || [],
          source: "resolve-probe",
        });
      }
    }
  }

  // 3. Add explicitly unrestricted/global commission-eligible merchants from /v2/merchant
  for (const m of globalDirectory.globalMerchants) {
    if (isBrokenTakeadsDomain(m.domain) || isForeignCountrySpecificMerchant(m, cc)) continue;
    if (!isMerchantCommissionEligibleForCountry(m)) continue;
    if (!merged.has(m.domain)) {
      merged.set(m.domain, m);
    }
  }

  const merchants = Array.from(merged.values());
  return {
    merchants,
    byDomain: indexMerchantsByDomain(merchants),
  };
}

function parseDealObject(raw: any, byDomain: Map<string, TakeadsMerchant>): TakeadsDeal | null {
  if (!raw || typeof raw !== "object") return null;

  const endsAt = cleanApiText(raw.endsAt || raw.endDate || raw.expiresAt || raw.dateEnd || "", 40);
  if (endsAt) {
    const ts = Date.parse(endsAt);
    if (!Number.isNaN(ts) && ts < Date.now()) {
      return null;
    }
  }

  const id = cleanApiText(raw.id ?? raw.couponId ?? "", 80);
  const title = cleanApiText(raw.title || raw.name || raw.shortName || "", 150);
  if (!id || !title) return null;

  const description = cleanApiText(raw.description || raw.details || "", 200);
  const code = cleanApiText(raw.code || raw.promoCode || raw.promocode || "", 40);
  const discount = cleanApiText(raw.discount || raw.discountValue || raw.saving || "", 40);
  const rawTrackingLink = isValidHttpsUrl(raw.trackingLink)
    ? raw.trackingLink.trim()
    : isValidHttpsUrl(raw.affiliateUrl)
      ? raw.affiliateUrl.trim()
      : "";
  const url = isValidHttpsUrl(raw.url)
    ? raw.url.trim()
    : isValidHttpsUrl(raw.landingUrl)
      ? raw.landingUrl.trim()
      : "";

  let domain = normalizeDomain(
    raw.domain || raw.defaultDomain || raw.merchantDomain || (url ? url : "")
  );
  let merchantName = cleanApiText(raw.merchantName || raw.firmName || raw.advertiserName || "", 80);
  const merchantId = cleanApiText(raw.merchantId ?? raw.advertiserId ?? "", 80);

  let matchedMerchant = domain ? byDomain.get(domain) : undefined;
  if (!matchedMerchant && merchantId) {
    for (const m of byDomain.values()) {
      if (m.id === merchantId) {
        matchedMerchant = m;
        break;
      }
    }
  }
  if (matchedMerchant && !isBrokenTakeadsDomain(matchedMerchant.domain)) {
    domain = matchedMerchant.domain;
    merchantName = matchedMerchant.name;
  } else {
    return null;
  }

  if (!domain) return null;
  const trackingLink = isGenuineTakeadsAffiliateLink(rawTrackingLink, domain, url) ? rawTrackingLink : "";
  if (!merchantName) merchantName = domain;

  return {
    id,
    merchantId: matchedMerchant.id || merchantId || domain,
    merchantName,
    domain,
    title,
    description,
    code,
    discount,
    trackingLink,
    url,
    endsAt,
  };
}

async function fetchTakeadsDealsForQuery(
  queryText: string,
  countryCode: string,
  byDomain: Map<string, TakeadsMerchant>,
  signal?: AbortSignal
): Promise<TakeadsDeal[]> {
  const publicKey = getTakeadsPublicKey();
  if (!publicKey || Date.now() < couponsApiUnavailableUntil) {
    return [];
  }

  const cleanQ = cleanApiText(queryText, 80);
  if (!cleanQ) return [];

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), TAKEADS_COUPON_TIMEOUT_MS);
  const onParentAbort = () => controller.abort();
  signal?.addEventListener("abort", onParentAbort, { once: true });

  try {
    const response = await fetch(TAKEADS_COUPON_SEARCH_ENDPOINT, {
      method: "POST",
      redirect: "error",
      headers: {
        Authorization: `Bearer ${publicKey}`,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({
        q: cleanQ,
        countryCode: countryCode.toUpperCase(),
        pageSize: 20,
        limit: 20,
        includeInactive: false,
      }),
      signal: controller.signal,
    });

    if (response.status === 401 || response.status === 403 || response.status === 404) {
      couponsApiUnavailableUntil = Date.now() + TAKEADS_COUPON_UNAVAILABLE_TTL_MS;
      return [];
    }

    if (!response.ok) {
      return [];
    }

    const payload: any = await response.json();
    const rawDeals = Array.isArray(payload?.data)
      ? payload.data
      : Array.isArray(payload?.coupons)
        ? payload.coupons
        : Array.isArray(payload?.items)
          ? payload.items
          : [];

    const deals: TakeadsDeal[] = [];
    const seen = new Set<string>();
    for (const raw of rawDeals) {
      const parsed = parseDealObject(raw, byDomain);
      if (parsed && !seen.has(parsed.id)) {
        seen.add(parsed.id);
        deals.push(parsed);
      }
      if (deals.length >= 15) break;
    }

    if (deals.length === 0 && !signal?.aborted) {
      const listUrl = `${TAKEADS_COUPON_LIST_ENDPOINT}?countryCode=${encodeURIComponent(countryCode.toUpperCase())}&limit=50`;
      const listResp = await fetch(listUrl, {
        method: "GET",
        redirect: "error",
        headers: {
          Authorization: `Bearer ${publicKey}`,
          Accept: "application/json",
        },
        signal: controller.signal,
      });
      if (listResp.ok) {
        const listPayload: any = await listResp.json();
        const listRaw = Array.isArray(listPayload?.data)
          ? listPayload.data
          : Array.isArray(listPayload?.coupons)
            ? listPayload.coupons
            : [];
        const queryTokens = extractSearchTokens(cleanQ);
        for (const raw of listRaw) {
          const parsed = parseDealObject(raw, byDomain);
          if (!parsed || seen.has(parsed.id)) continue;
          const hay = `${parsed.title} ${parsed.description} ${parsed.merchantName}`.toLowerCase();
          if (queryTokens.some((tok) => hay.includes(tok))) {
            seen.add(parsed.id);
            deals.push(parsed);
            if (deals.length >= 12) break;
          }
        }
      }
    }

    return deals;
  } catch {
    return [];
  } finally {
    clearTimeout(timeoutId);
    signal?.removeEventListener("abort", onParentAbort);
  }
}

function extractSearchTokens(text: string): string[] {
  const stopWords = new Set([
    "the", "and", "for", "with", "from", "buy", "best", "cheap", "price", "online", "store", "shop",
    "black", "white", "red", "blue", "green", "gold", "silver", "pink", "brown", "gray", "grey", "new", "original",
    "من", "في", "على", "عن", "مع", "أفضل", "افضل", "ارخص", "أرخص", "سعر", "بديل", "بدائل", "شراء", "متجر",
    "اسود", "أسود", "سوداء", "ابيض", "أبيض", "بيضاء", "احمر", "أحمر", "ازرق", "أزرق", "ذهبي", "فضي", "رجالي", "نسائي", "اصلي", "أصلي",
  ]);
  const clean = (text || "")
    .toLowerCase()
    .replace(/https?:\/\/\S+/g, " ")
    .replace(/[^\p{L}\p{N}\s]+/gu, " ")
    .trim();
  const parts = clean.split(/\s+/).filter((w) => w.length >= 2 && !stopWords.has(w));
  return Array.from(new Set(parts)).slice(0, 16);
}

// -------------------------------------------------------------------------
// Granular Universal Product Vertical Classification & Hard Filtering
// -------------------------------------------------------------------------

interface ProductVerticalRule {
  id: string;
  label: string;
  match: RegExp;
  storeTags: string[];
}

const PRODUCT_VERTICALS: ProductVerticalRule[] = [
  {
    id: "smartwatches",
    label: "Smartwatches & Wearables",
    match: /ساعة\s*ذكية|ساعات\s*ذكية|ساعه\s*ذكيه|ابل\s*واتش|آبل\s*واتش|جالكسي\s*واتش|سمارت\s*واتش|ساعة\s*سامسونج|ساعة\s*هواوي|ساعة\s*رياضية\s*ذكية|سوار\s*ذكي|سوار\s*رياضي|smartwatch|smart\s*watch|apple\s*watch|galaxy\s*watch|garmin|fitbit|amazfit|huawei\s*watch|whoop|wearable|fitness\s*tracker/i,
    storeTags: ["smartwatches", "wearables"],
  },
  {
    id: "watches",
    label: "Watches & Timepieces",
    match: /(?:^|[\s،,.])(ساعة|ساعات|ساعه|ساعتي|wristwatch|wrist\s*watch|timepiece|chronograph|watches|watch|rolex|casio|seiko|tissot|omega|fossil|citizen|g-shock|swatch|hublot|tag\s*heuer|orient|longines|movado|hamilton|bulova|invicta)(?=$|[\s،,.!?؟])/i,
    storeTags: ["watches", "timepieces", "department"],
  },
  {
    id: "perfumes",
    label: "Perfumes & Fragrances",
    match: /عطر|عطور|برفان|بارفان|عود|دهن\s*عود|بخور|مبخرة|مبخر|مسك|معطر\s*جسم|perfume|fragrance|cologne|eau\s*de\s*parfum|eau\s*de\s*toilette|oud|scent|parfum/i,
    storeTags: ["perfume", "fragrance", "department"],
  },
  {
    id: "beauty_skincare",
    label: "Beauty, Skincare & Makeup",
    match: /مكياج|أدوات\s*تجميل|ادوات\s*تجميل|تجميل|بشرة|سيروم|كريم|واقي\s*شمس|شامبو|بلسم|عناية\s*بالشعر|مرطب|ماسك|أحمر\s*شفاه|احمر\s*شفاه|روج|ماسكارا|مسكرة|فاونديشن|كونسيلر|غسول|تونر|لوشن|مناكير|كحل|استشوار|سشوار|فير\s*شعر|مكينة\s*حلاقة|ماكينة\s*حلاقة|makeup|skincare|cosmetic|serum|moisturizer|sunscreen|shampoo|conditioner|haircare|hair\s*dryer|lipstick|mascara|foundation|cleanser|toner|retinol|beauty/i,
    storeTags: ["beauty", "skincare", "makeup", "haircare", "cosmetics", "department"],
  },
  {
    id: "health_supplements",
    label: "Health, Vitamins & Supplements",
    match: /فيتامين|فيتامينات|مكمل|مكملات|بروتين|كرياتين|أوميغا|اوميغا|كولاجين|ماغنيسيوم|مغنيسيوم|زنك|حديد|أعشاب|اعشاب|عضوي|vitamin|supplement|protein|whey|creatine|omega|collagen|magnesium|zinc|probiotic|herbal|nutrition|wellness|pharmacy/i,
    storeTags: ["health", "vitamins", "supplements", "nutrition", "pharmacy"],
  },
  {
    id: "phones_tablets",
    label: "Smartphones & Tablets",
    match: /جوال|جوالات|هاتف|هواتف|موبايل|ايفون|آيفون|آيباد|ايباد|تابلت|جالكسي|شاومي|هواوي|أونر|اونر|بكسل|smartphone|iphone|ipad|tablet|galaxy\s*[szaf]|pixel|xiaomi|redmi|oneplus|\bphone\b|\bmobile\b/i,
    storeTags: ["phones", "tablets", "smartphones"],
  },
  {
    id: "laptops_computers",
    label: "Laptops, Computers & Peripherals",
    match: /لابتوب|لاب\s*توب|كمبيوتر|حاسوب|ماك\s*بوك|ماكبوك|شاشة\s*كمبيوتر|شاشة\s*قيمنق|كيبورد|لوحة\s*مفاتيح|ماوس|فأرة|كرت\s*شاشة|معالج|رام|هارد|قرص\s*صلب|طابعة|راوتر|laptop|macbook|computer|desktop|pc\s*part|monitor|keyboard|mouse|gpu|cpu|ssd|printer|router|notebook|thinkpad/i,
    storeTags: ["laptops", "computers", "pc parts", "monitors", "printers"],
  },
  {
    id: "audio_headphones",
    label: "Headphones, Earbuds & Audio",
    match: /سماعة|سماعات|سماعه|ايربودز|إيربودز|هيدفون|سبيكر|مكبر\s*صوت|ساوند\s*بار|ميكروفون|مايك|headphone|earbud|earphone|airpods|speaker|soundbar|microphone|audio|headset|buds/i,
    storeTags: ["audio", "headphones", "earbuds", "speakers"],
  },
  {
    id: "chargers_accessories",
    label: "Chargers, Power Banks & Cables",
    match: /شاحن|باور\s*بانك|باوربانك|بطارية\s*متنقلة|كابل|كيبل|سلك\s*شاحن|كفر\s*جوال|جراب|حامي\s*شاشة|توصيلة|فيش|محول|charger|powerbank|power\s*bank|cable|adapter|phone\s*case|screen\s*protector|usb-c|magsafe|dock/i,
    storeTags: ["chargers", "powerbank", "cables", "phone accessories"],
  },
  {
    id: "gaming",
    label: "Gaming Consoles & Gear",
    match: /بلايستيشن|بلاي\s*ستيشن|اكس\s*بوكس|إكس\s*بوكس|نينتندو|سويتش|يد\s*تحكم|يد\s*سوني|قيمنق|جيمنج|ألعاب\s*فيديو|كرسي\s*قيمنق|playstation|ps5|xbox|nintendo|switch|gaming|controller|joystick|console|steam\s*deck/i,
    storeTags: ["gaming", "consoles"],
  },
  {
    id: "cameras_drones",
    label: "Cameras, Photography & Drones",
    match: /كاميرا|عدسة|درون|طائرة\s*بدون\s*طيار|ترايبود|حامل\s*كاميرا|جو\s*برو|غو\s*برو|camera|dslr|mirrorless|lens|drone|tripod|gopro|gimbal|photography|webcam/i,
    storeTags: ["cameras", "drones", "rc", "photography"],
  },
  {
    id: "tv_home_electronics",
    label: "TVs & Projectors",
    match: /تلفزيون|تلفاز|شاشة\s*تلفزيون|بروجكتر|بروجيكتور|\btv\b|television|oled|qled|projector|smart\s*tv|home\s*theater/i,
    storeTags: ["tv", "televisions", "projectors"],
  },
  {
    id: "shoes_sneakers",
    label: "Shoes & Sneakers",
    match: /حذاء|أحذية|احذية|جزمة|جزمه|جزم|كندرة|كنادر|شوز|سنيكرز|سنيكر|كوتشي|صندل|شبشب|شحاطة|نعال|بسطار|بوت|كعب|shoe|shoes|sneaker|sneakers|boot|boots|sandal|heel|loafer|footwear|slipper|jordan|yeezy|air\s*max|ultraboost/i,
    storeTags: ["shoes", "sneakers", "footwear", "department"],
  },
  {
    id: "bags_luggage",
    label: "Bags, Handbags & Luggage",
    match: /شنطة|شنطه|شنط|حقيبة|حقائب|باك\s*باك|محفظة|بوك|شنطة\s*سفر|حقيبة\s*ظهر|حقيبة\s*لابتوب|\bbag\b|\bbags\b|handbag|backpack|luggage|suitcase|tote|wallet|purse|crossbody|clutch|duffel/i,
    storeTags: ["bags", "luggage", "handbags", "backpacks", "department"],
  },
  {
    id: "clothing_apparel",
    label: "Clothing & Apparel",
    match: /فستان|فساتين|ملابس|تيشيرت|تي\s*شيرت|قميص|بلوزة|جاكيت|معطف|بنطلون|جينز|شورت|عباية|عبايات|طرحة|ثوب|شماغ|غترة|بشت|بدلة|هودي|سويتر|بلوفر|كنزة|تنورة|بيجامة|dress|shirt|t-shirt|jacket|coat|jeans|pants|trousers|shorts|hoodie|sweater|suit|abaya|skirt|pajama|clothing|apparel|outfit|blouse|leggings/i,
    storeTags: ["clothing", "apparel", "department"],
  },
  {
    id: "jewelry_accessories",
    label: "Jewelry & Fine Accessories",
    match: /خاتم|سلسال|عقد|سوار|اسوارة|إسوارة|حلق|أقراط|مجوهرات|ذهب|فضة|ألماس|الماس|بروش|jewelry|jewellery|necklace|bracelet|ring|earring|pendant|diamond|charm|swarovski|pandora/i,
    storeTags: ["jewelry", "jewellery", "department"],
  },
  {
    id: "eyewear",
    label: "Sunglasses & Eyewear",
    match: /نظارة|نظارات|نظاره|شمسية|sunglass|eyewear|glasses|ray-ban|oakley/i,
    storeTags: ["eyewear", "sunglasses", "department"],
  },
  {
    id: "kitchen_appliances",
    label: "Kitchen & Home Appliances",
    match: /أدوات\s*مطبخ|ادوات\s*مطبخ|أدوات\s*منزلية|ادوات\s*منزلية|أجهزة\s*منزلية|اجهزة\s*منزلية|قهوة|ماكينة\s*قهوة|اسبريسو|قلاية\s*هوائية|قلاية|خلاط|مطحنة|عصارة|عجانة|ميكروويف|ميكرويف|فرن|غلاية|مكنسة|مكيف|ثلاجة|غسالة|مجفف|نشافة|مكواة|مكوى|دفاية|مروحة|برادة|فلتر\s*ماء|مطبخ|قدور|طنجرة|مقلاة|أواني|اواني|ترامس|دلة|coffee|espresso|air\s*fryer|blender|mixer|microwave|oven|kettle|vacuum|fridge|refrigerator|washer|dryer|dishwasher|iron|kitchen|cookware|appliance|dyson|nespresso/i,
    storeTags: ["kitchen", "appliances", "cookware", "vacuums", "department"],
  },
  {
    id: "home_furniture",
    label: "Furniture, Bedding & Home Decor",
    match: /أثاث|اثاث|كنب|كنبة|سرير|مرتبة|مفرش|مفارش|بطانية|لحاف|مخدة|وسادة|طاولة|طاولات|مكتب|كرسي|كراسي|خزانة|دولاب|سجادة|سجاد|زولية|ستارة|ستائر|إضاءة|اضاءة|مصباح|ديكور|تحف|شموع|furniture|sofa|couch|bed|mattress|bedding|blanket|pillow|table|desk|chair|wardrobe|rug|carpet|curtain|lighting|lamp|decor|candle|shelf/i,
    storeTags: ["furniture", "bedding", "decor", "lighting", "rugs", "department"],
  },
  {
    id: "sports_outdoor",
    label: "Sports, Fitness & Outdoor",
    match: /رياضة|رياضي|رياضية|جيم|لياقة|دمبل|أوزان|جهاز\s*مشي|دراجة|دراجه|سيكل|سكوتر|تخييم|خيمة|رحلات|سباحة|كرة\s*قدم|مضرب|تنس|بادل|يوغا|يوجا|جري|sport|fitness|gym|dumbbell|weights|bike|bicycle|ebike|scooter|camping|tent|outdoor|hiking|swim|football|soccer|padel|tennis|yoga|treadmill|running/i,
    storeTags: ["sports", "fitness", "outdoor", "camping", "cycling", "ebikes", "running", "sportswear"],
  },
  {
    id: "toys_baby",
    label: "Toys & Baby Products",
    match: /ألعاب\s*أطفال|العاب\s*اطفال|لعبة|دمية|ليغو|ليجو|أطفال|اطفال|رضيع|مواليد|عربة\s*أطفال|عربية\s*طفل|كرسي\s*سيارة|حفاضات|رضاعة|toy|toys|lego|doll|puzzle|baby|infant|stroller|car\s*seat|diaper|kids|nursery|crib/i,
    storeTags: ["toys", "baby", "kids"],
  },
  {
    id: "tools_hardware_auto",
    label: "Tools, Hardware, Garden & Auto",
    match: /أدوات\s*(?:كهربائية|صيانة|نجارة|سباكة|حديقة|السيارة|بناء|يدوية)|ادوات\s*(?:كهربائية|صيانة|نجارة|سباكة|حديقة|السيارة|بناء|يدوية)|عدة\s*(?:صيانة|تصليح|يدوية)|دريل|مثقاب|مفك|مفكات|منشار|لحام|حديقة|مضخة|منفاخ|طرمبة|سيارة|سيارات|إطارات|كفرات|داش\s*كام|كاميرا\s*سيارة|اكسسوارات\s*سيارة|power\s*tool|hand\s*tool|drill|hardware|wrench|screwdriver|saw|garden|home\s*improvement|auto\s*parts|automotive|dash\s*cam|tire|\bcar\s+accessories\b/i,
    storeTags: ["tools", "hardware", "home improvement", "garden", "auto", "automotive"],
  },
  {
    id: "books_office",
    label: "Books & Office Supplies",
    match: /كتاب|كتب|رواية|قرطاسية|دفتر|أقلام|اقلام|قلم|مكتبة|أدوات\s*مكتبية|ادوات\s*مكتبية|book|books|novel|stationery|notebook|office\s*supplies/i,
    storeTags: ["books", "stationery", "office"],
  },
];

function detectProductVerticals(combinedQuery: string): ProductVerticalRule[] {
  let matched: ProductVerticalRule[] = [];
  for (const rule of PRODUCT_VERTICALS) {
    if (rule.match.test(combinedQuery)) {
      matched.push(rule);
    }
  }
  if (matched.length <= 1) return matched;

  const hasId = (id: string) => matched.some((r) => r.id === id);

  // 1. Disambiguate smartwatches vs classic watches
  if (hasId("smartwatches") && hasId("watches")) {
    const mentionsClassicBrand = /rolex|casio|seiko|tissot|omega|fossil|citizen|g-shock|swatch|hublot|tag\s*heuer|orient|longines|كلاسيك|عقارب|ميكانيك|أوتوماتيك/i.test(combinedQuery);
    if (!mentionsClassicBrand) {
      matched = matched.filter((r) => r.id !== "watches");
    }
  }

  // 2. Prevent modifier adjectives ("رياضي/رياضية/running/sport") on shoes/watches/clothing/bags/audio from pulling in camping/bicycle stores
  const specificWearableOrApparel =
    hasId("shoes_sneakers") || hasId("watches") || hasId("smartwatches") ||
    hasId("clothing_apparel") || hasId("bags_luggage") || hasId("eyewear") || hasId("audio_headphones");
  if (specificWearableOrApparel && hasId("sports_outdoor")) {
    const explicitEquipment = /دراجة|دراجه|سيكل|سكوتر|تخييم|خيمة|دمبل|أوزان|جهاز\s*مشي|كرة|مضرب|تنس|بادل|يوغا|يوجا|bike|bicycle|ebike|scooter|camping|tent|dumbbell|weights|treadmill|yoga|racket|ball/i.test(combinedQuery);
    if (!explicitEquipment) {
      matched = matched.filter((r) => r.id !== "sports_outdoor");
    }
  }

  // 3. Prevent audience word ("أطفال/kids") on shoes/clothing/watches/bags from pulling in toy/LEGO stores
  if (specificWearableOrApparel && hasId("toys_baby")) {
    const explicitToyOrBabyGear = /ألعاب|العاب|لعبة|دمية|ليغو|ليجو|عربة|عربية|حفاضات|رضاعة|سرير\s*طفل|toy|toys|lego|doll|puzzle|stroller|diaper|crib/i.test(combinedQuery);
    if (!explicitToyOrBabyGear) {
      matched = matched.filter((r) => r.id !== "toys_baby");
    }
  }

  // 4. Desk/office furniture ("كرسي مكتب" / "طاولة مكتب") belongs to furniture, not bookstores
  if (hasId("home_furniture") && hasId("books_office")) {
    const explicitBooks = /كتاب|كتب|رواية|قرطاسية|دفتر|أقلام|اقلام|book|novel|stationery|notebook/i.test(combinedQuery);
    if (!explicitBooks) {
      matched = matched.filter((r) => r.id !== "books_office");
    }
  }

  // 5. Baby car seat ("كرسي سيارة") belongs to toys_baby, not auto hardware/furniture
  if (hasId("toys_baby") && /كرسي\s*سيارة|car\s*seat/i.test(combinedQuery)) {
    matched = matched.filter((r) => r.id !== "tools_hardware_auto" && r.id !== "home_furniture");
  }

  // 6. Gaming chair/monitor/laptop: keep laptops/gaming clean without pulling in unrelated furniture unless "كرسي"
  if (hasId("laptops_computers") && hasId("tv_home_electronics")) {
    if (!/تلفزيون|تلفاز|بروجكتر|بروجيكتور|\btv\b|television|projector/i.test(combinedQuery)) {
      matched = matched.filter((r) => r.id !== "tv_home_electronics");
    }
  }

  return matched;
}

function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function textMatchesTagWordBoundary(hay: string, tag: string): boolean {
  const cleanTag = tag.toLowerCase().trim();
  if (!cleanTag) return false;
  const rx = new RegExp(`(?:^|[^a-z])${escapeRegExp(cleanTag)}(?:s|es)?(?:$|[^a-z])`, "i");
  return rx.test(hay);
}

interface ScoredMerchant {
  merchant: TakeadsMerchant;
  score: number;
  isCategoryMatch: boolean;
  matchedTagCount: number;
  isGeneralMarketplace: boolean;
  hasBrandTokenMatch: boolean;
}

function evaluateMerchantForQuery(
  merchant: TakeadsMerchant,
  countryCode: string,
  tokens: string[],
  allowedTags: Set<string>,
  hasDetectedVertical: boolean,
  dealMerchantDomains: Set<string>,
  queryMentionsNonRetail: boolean
): ScoredMerchant | null {
  const cc = countryCode.toUpperCase();
  const catText = merchant.categories.join(" ");
  const structuredHay = `${merchant.name} ${merchant.domain} ${catText}`.toLowerCase();
  const fullHay = `${structuredHay} ${merchant.description}`.toLowerCase();
  // Match category tags strictly against structured categories + store name/domain (only fall back to description if categories are empty)
  const tagSearchHay = merchant.categories.length > 0 ? structuredHay : fullHay;

  // Filter out non-shopping services (VPN, hosting, hotels, airlines, finance, gambling) from /v2/merchant
  if (!queryMentionsNonRetail && merchant.source === "merchant-api" && !MAJOR_RETAIL_DOMAINS.has(merchant.domain)) {
    if (NON_RETAIL_SERVICE_PATTERN.test(fullHay)) {
      return null;
    }
  }

  const isGeneralMarketplace = TRUE_GENERAL_MARKETPLACES.has(merchant.domain);
  let score = 0;

  if (merchant.countryCodes.includes(cc)) {
    score += 40;
  } else if (merchant.countryCodes.length === 0) {
    score += 12;
  }

  const hasDeal = dealMerchantDomains.has(merchant.domain);
  if (hasDeal) {
    score += 55;
  }

  if (MAJOR_RETAIL_DOMAINS.has(merchant.domain)) {
    score += 30;
  }

  let hasBrandTokenMatch = false;
  const lowerName = merchant.name.toLowerCase();
  const brandRoot = extractBrandRootLabel(merchant.domain);
  for (const tok of tokens) {
    if (tok.length >= 3 && (lowerName.includes(tok) || brandRoot === tok || merchant.domain.includes(tok))) {
      score += 65;
      hasBrandTokenMatch = true;
    } else if (fullHay.includes(tok)) {
      score += 18;
    }
  }

  let matchedTagCount = 0;
  for (const tag of allowedTags) {
    if (textMatchesTagWordBoundary(tagSearchHay, tag)) {
      matchedTagCount++;
      score += 32;
    }
  }

  // Reward dedicated specialty stores when they directly match the detected vertical
  if (matchedTagCount > 0 && !isGeneralMarketplace) {
    score += 25;
  }

  // Strongly prioritize local country ccTLD stores (e.g. amazon.sa in SA, amazon.co.uk in GB, amazon.de in DE)
  const lowerCc = (countryCode || "US").toLowerCase();
  const domLower = merchant.domain.toLowerCase();
  const isExactCcTld =
    domLower.endsWith(`.${lowerCc}`) ||
    (lowerCc === "gb" && domLower.endsWith(".co.uk")) ||
    (lowerCc === "au" && domLower.endsWith(".com.au")) ||
    (lowerCc === "jp" && domLower.endsWith(".co.jp")) ||
    (lowerCc === "br" && domLower.endsWith(".com.br")) ||
    (lowerCc === "mx" && domLower.endsWith(".com.mx")) ||
    (lowerCc === "sa" && domLower.startsWith("saudi."));
  if (isExactCcTld) {
    score += 48;
  } else if (merchant.countryCodes.includes(countryCode.toUpperCase())) {
    score += 22;
  }

  if (merchant.hasVerifiedCommission) {
    score += 18;
  }

  if (merchant.isDeeplinkEnabled) {
    score += 6;
  }

  // Strict category eligibility when a product vertical was detected:
  // MUST either match the vertical's exact allowed tags, be a true general multi-category marketplace,
  // or match an explicit brand token from the query. (Deals boost score but NEVER bypass vertical matching!)
  const isCategoryMatch = !hasDetectedVertical
    ? true
    : (matchedTagCount > 0 || isGeneralMarketplace || hasBrandTokenMatch);

  return {
    merchant,
    score,
    isCategoryMatch,
    matchedTagCount,
    isGeneralMarketplace,
    hasBrandTokenMatch,
  };
}

export interface TakeadsGroundingContext {
  ok: boolean;
  errorCode?: "NOT_CONFIGURED" | "AUTH_ERROR" | "CATALOG_EMPTY";
  countryCode: string;
  merchants: TakeadsMerchant[];
  selectedMerchants: TakeadsMerchant[];
  allowedDomains: Set<string>;
  detectedCategories: string[];
  byDomain: Map<string, TakeadsMerchant>;
  deals: TakeadsDeal[];
  dealsById: Map<string, TakeadsDeal>;
  promptDataBlock: string;
  sampleStore: string;
  sampleDomain: string;
}

function getDirectCatalogMerchantsForCountry(
  countryCode: string
): { merchants: TakeadsMerchant[]; byDomain: Map<string, TakeadsMerchant> } {
  const cc = (countryCode || "US").toUpperCase();
  const region = getRegionForCountry(cc);
  const merged = new Map<string, TakeadsMerchant>();

  for (const c of CANDIDATE_STORES) {
    const dom = normalizeDomain(c.domain);
    if (!dom) continue;
    const isRegionalMatch = c.regions.includes(region);
    const isGlobalMatch = c.regions.includes("GLOBAL");
    if (!isRegionalMatch && !isGlobalMatch) continue;

    const candidateMerchant: TakeadsMerchant = {
      id: dom,
      name: c.name,
      domain: dom,
      domains: [dom],
      countryCodes: isRegionalMatch ? [cc] : [],
      categories: c.categories,
      description: c.categories.join(", "),
      trackingLink: c.probeUrl,
      isDeeplinkEnabled: true,
      hasVerifiedCommission: true,
      maxCommissionValue: 0,
      commissionCountries: [],
      source: "resolve-probe",
    };

    if (isForeignCountrySpecificMerchant(candidateMerchant, cc)) continue;
    merged.set(dom, candidateMerchant);
  }

  const merchants = Array.from(merged.values());
  return {
    merchants,
    byDomain: indexMerchantsByDomain(merchants),
  };
}

export async function buildTakeadsGroundingContext(
  countryCode: string,
  queryText: string,
  extraContextText: string = "",
  _signal?: AbortSignal
): Promise<TakeadsGroundingContext> {
  const cc = (countryCode || "US").toUpperCase();

  const emptyResult = (errorCode: TakeadsGroundingContext["errorCode"]): TakeadsGroundingContext => ({
    ok: false,
    errorCode,
    countryCode: cc,
    merchants: [],
    selectedMerchants: [],
    allowedDomains: new Set(),
    detectedCategories: [],
    byDomain: new Map(),
    deals: [],
    dealsById: new Map(),
    promptDataBlock: "",
    sampleStore: "",
    sampleDomain: "",
  });

  // Direct curated store catalog mode: clean country-matched store search URLs are returned directly
  // so the client-side ConvertLink JS snippet (index.html) monetizes clicks using the user's real Geo-IP.
  const catalogRes = getDirectCatalogMerchantsForCountry(cc);
  if (catalogRes.merchants.length === 0) {
    return emptyResult("CATALOG_EMPTY");
  }

  const combinedQuery = `${queryText} ${extraContextText}`.trim();
  const deals: TakeadsDeal[] = [];
  const dealsById = new Map<string, TakeadsDeal>();
  const dealMerchantDomains = new Set<string>();

  const tokens = extractSearchTokens(combinedQuery);
  const matchedVerticals = detectProductVerticals(combinedQuery);
  const hasDetectedVertical = matchedVerticals.length > 0;
  const detectedCategories = matchedVerticals.map((v) => v.label);

  const allowedTags = new Set<string>();
  for (const v of matchedVerticals) {
    for (const tag of v.storeTags) {
      allowedTags.add(tag);
    }
  }

  const queryMentionsNonRetail = NON_RETAIL_SERVICE_PATTERN.test(combinedQuery) || /فندق|طيران|حجز|تأمين|استضافة|vpn|سفر/i.test(combinedQuery);

  const evaluated: ScoredMerchant[] = [];
  for (const m of catalogRes.merchants) {
    const ev = evaluateMerchantForQuery(
      m,
      cc,
      tokens,
      allowedTags,
      hasDetectedVertical,
      dealMerchantDomains,
      queryMentionsNonRetail
    );
    if (ev) evaluated.push(ev);
  }

  evaluated.sort((a, b) => b.score - a.score);

  let candidatePool: ScoredMerchant[];
  if (hasDetectedVertical) {
    const strictMatches = evaluated.filter((e) => e.isCategoryMatch);
    if (strictMatches.length >= 2) {
      candidatePool = strictMatches.slice(0, 34);
    } else {
      const fallback = evaluated.filter((e) => e.isCategoryMatch || e.isGeneralMarketplace);
      candidatePool = (fallback.length > 0 ? fallback : evaluated.filter((e) => e.isGeneralMarketplace)).slice(0, 22);
      if (candidatePool.length === 0) {
        candidatePool = evaluated.slice(0, 14);
      }
    }
  } else {
    candidatePool = evaluated.slice(0, 32);
  }

  const maxShortlist = hasDetectedVertical ? 16 : 18;
  const seenShortlistBrands = new Set<string>();
  const selectedScored: ScoredMerchant[] = [];
  for (const s of candidatePool) {
    const m = s.merchant;
    const brandRoot = extractBrandRootLabel(m.domain);
    if (brandRoot && brandRoot.length >= 3 && seenShortlistBrands.has(brandRoot)) continue;
    if (brandRoot && brandRoot.length >= 3) seenShortlistBrands.add(brandRoot);
    selectedScored.push(s);
    if (selectedScored.length >= maxShortlist) break;
  }

  if (selectedScored.length === 0) {
    return emptyResult("CATALOG_EMPTY");
  }

  const selectedMerchants = selectedScored.map((s) => s.merchant);
  const allowedDomains = new Set<string>();
  for (const m of selectedMerchants) {
    allowedDomains.add(m.domain);
    for (const d of m.domains) allowedDomains.add(d);
  }

  const merchantLines = selectedMerchants.map((m) => {
    const metaParts: string[] = [];
    if (m.categories.length > 0) metaParts.push(`categories: ${m.categories.slice(0, 6).join(", ")}`);
    if (m.description && m.description.toLowerCase() !== m.categories.join(", ").toLowerCase()) {
      metaParts.push(`info: ${m.description.slice(0, 85)}`);
    }
    if (m.countryCodes.length > 0) metaParts.push(`countries: ${m.countryCodes.slice(0, 6).join(",")}`);
    const suffix = metaParts.length > 0 ? ` | ${metaParts.join(" | ")}` : "";
    return `- ${m.name} | domain: ${m.domain}${suffix}`;
  });

  const dealLines = deals
    .filter((d) => allowedDomains.has(d.domain))
    .slice(0, 12)
    .map((d) => {
      const parts = [`dealId: ${d.id}`, `store: ${d.merchantName}`, `domain: ${d.domain}`, `title: ${d.title}`];
      if (d.discount) parts.push(`discount: ${d.discount}`);
      if (d.code) parts.push(`code: ${d.code}`);
      return `- ${parts.join(" | ")}`;
    });

  const categoryHeader = detectedCategories.length > 0
    ? `DETECTED_PRODUCT_CATEGORY: ${detectedCategories.join(" / ")}\n`
    : "";

  let promptDataBlock = `${categoryHeader}AVAILABLE_STORES (${selectedMerchants.length} verified relevant stores for ${cc}):\n${merchantLines.join("\n")}`;
  if (dealLines.length > 0) {
    promptDataBlock += `\n\nACTIVE_DEALS (${dealLines.length} verified active deals/coupons):\n${dealLines.join("\n")}`;
  }

  const sample = selectedMerchants[0];
  return {
    ok: true,
    countryCode: cc,
    merchants: catalogRes.merchants,
    selectedMerchants,
    allowedDomains,
    detectedCategories,
    byDomain: catalogRes.byDomain,
    deals,
    dealsById,
    promptDataBlock,
    sampleStore: sample.name,
    sampleDomain: sample.domain,
  };
}

function findVerifiedMerchantInCatalog(
  rawDomain: string | undefined,
  rawStore: string | undefined,
  context: TakeadsGroundingContext
): TakeadsMerchant | null {
  const dom = normalizeDomain(rawDomain || "");
  if (dom) {
    const exact = context.byDomain.get(dom);
    if (exact) return exact;

    const parts = dom.split(".");
    for (let i = 1; i < parts.length - 1; i++) {
      const parent = parts.slice(i).join(".");
      const found = context.byDomain.get(parent);
      if (found) return found;
    }

    const targetRoot = extractBrandRootLabel(dom);
    if (targetRoot.length >= 3) {
      for (const m of context.selectedMerchants) {
        if (extractBrandRootLabel(m.domain) === targetRoot) {
          return m;
        }
      }
    }
  }

  const cleanStore = (rawStore || "").toLowerCase().trim();
  if (cleanStore.length >= 2) {
    for (const m of context.selectedMerchants) {
      if (m.name.toLowerCase().trim() === cleanStore) {
        return m;
      }
    }
  }

  return null;
}

/**
 * Strictly grounds every AI output item in verified, category-aligned, link-healthy Takeads API data:
 * - Drops ANY store not in the filtered vertical-relevant Takeads catalog (`context.allowedDomains`).
 * - Resolves every outbound URL via Takeads PUT /v2/resolve (or verified merchant trackingLink).
 * - Verifies multi-hop redirect health for any merchant not yet cached in `domainHealthCache` so broken links NEVER reach users.
 * - Eliminates hallucinated prices (only allows verified deal discount/code, otherwise "-").
 */
export async function enforceTakeadsGroundedAlternatives<
  T extends {
    name: string;
    store: string;
    storeDomain?: string;
    exactUrl: string;
    link?: string;
    price: string;
    description: string;
    similarity: string;
    searchKey?: string;
    logoUrl?: string;
    imageUrl?: string;
    dealId?: string;
    isPromo?: boolean;
  }
>(
  items: T[],
  context: TakeadsGroundingContext,
  _signal?: AbortSignal,
  _perSearchCache?: Map<string, string | null>
): Promise<T[]> {
  if (!items || items.length === 0 || !context.ok) return [];

  const finalItems: T[] = [];
  const seenDomains = new Set<string>();
  const seenBrands = new Set<string>();

  const scrubInternal = (val: string): string =>
    (val || "")
      .replace(/\s*(?:عبر|من|في|ضمن\s+بيانات|على)\s+takeads(?:\s+api)?/gi, "")
      .replace(/\s*(?:via|from|in|by|on)\s+takeads(?:\s+api)?/gi, "")
      .replace(/\btakeads(?:\s+api)?\b/gi, "")
      .replace(/\s{2,}/g, " ")
      .trim();

  for (const item of items) {
    const merchant = findVerifiedMerchantInCatalog(item.storeDomain, item.store, context);
    if (!merchant) continue;

    // STRICT CATEGORY GUARD: reject any store outside the filtered vertical-relevant shortlist
    if (context.allowedDomains.size > 0 && !context.allowedDomains.has(merchant.domain)) {
      continue;
    }

    const normDom = normalizeDomain(merchant.domain);
    if (!normDom || seenDomains.has(normDom)) continue;

    const brandRoot = extractBrandRootLabel(normDom);
    if (brandRoot && brandRoot.length >= 3 && seenBrands.has(brandRoot)) continue;

    // Clean, direct HTTPS store search URL (ConvertLink JS tag handles client-side affiliate monetization per user Geo-IP)
    const directStoreUrl = (item.exactUrl || "").trim();
    if (!isValidHttpsUrl(directStoreUrl) || !isSafePublicHttpUrl(directStoreUrl) || isBareStoreHomepageUrl(directStoreUrl)) {
      continue;
    }

    seenDomains.add(normDom);
    if (brandRoot && brandRoot.length >= 3) seenBrands.add(brandRoot);

    const canonicalLogo = `https://www.google.com/s2/favicons?domain=${encodeURIComponent(merchant.domain)}&sz=128`;

    finalItems.push({
      ...item,
      name: scrubInternal(item.name).slice(0, 160) || merchant.name,
      store: merchant.name,
      storeDomain: merchant.domain,
      price: "-",
      description: scrubInternal(item.description).slice(0, 220),
      logoUrl: canonicalLogo,
      imageUrl: canonicalLogo,
      exactUrl: directStoreUrl,
      link: directStoreUrl,
      isPromo: false,
      dealId: undefined,
    });
  }

  return finalItems;
}
