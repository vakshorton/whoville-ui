package com.hortonworks.whoville.controller;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.net.util.Base64;
import org.codehaus.jackson.map.ObjectMapper;
import org.codehaus.jettison.json.JSONArray;
import org.codehaus.jettison.json.JSONException;
import org.codehaus.jettison.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
//import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.Lists;

@Component
@RestController
public class Controller{
	static final Logger LOG = LoggerFactory.getLogger(Controller.class);
	
	@Value("${whoville.api.host}")
	private String whovilleHost;
	
	@Value("${whoville.api.port}")
	private String whovillePort;
	
	@Value("${dps.admin.user}")
	private String dpsAdminUserName;
	
	@Value("${dps.admin.password}")
	private String dpsAdminPassword; 
	
	private String whovilleUrl;
	private String whovilleApiUri = "/api/whoville/v1";
	private String whovilleMenuUri = "/getMenu";
	private String whovilleCredentialUri = "/getCredentials";
	private String whovilleDeployPackagUri = "/deployPackage";
	private String whovilleStacksUri = "/getStacks";
	private String whovilleCBUri = "/getCB";
	
	private String dpsHost;
	private String dpsUrl;
	private String dps_auth_uri = "/knox/gateway/knoxsso/api/v1/websso?originalUrl=";//"/auth/in";
	private String dps_clusters_uri = "/api/actions/clusters?type=all";
	private String dlm_clusters_uri = "/dlm/api/clusters";
	private String dlm_policies_uri = "/dlm/api/policies?numResults=200&instanceCount=10";
	private String dss_collections_uri = "/dss/api/dataset/list/tag/ALL?offset=0&size=10";//"/api/dataset/list/tag/ALL?offset=0&size=10";
	private String dss_dataset_uri = "/dss/api/dataset"; //dss/api/actions/clusters?type=all
	private String dss_assets_uri = "/dss/api/assets/details";//"/dss/api/assets/details";
	
	private String oAuthToken = null;

	public Controller() {
		initializeTrustManager();
	}
	
	@PostConstruct
    public void init() {
        whovilleUrl = "http://" + whovilleHost + ":" + whovillePort;
    }
	
	@SuppressWarnings("unchecked")
	@RequestMapping(value="/getMenu", method=RequestMethod.GET, produces = { MediaType.APPLICATION_JSON_VALUE})
    public HashMap<String, String> getWhovilleMenu() {
		
		String urlString = whovilleUrl + whovilleApiUri + whovilleMenuUri;
	    HashMap<String, String> menu = new HashMap<String,String>();
	    JSONObject menuJSON = httpGetObject(urlString, "", false);
		
	    menuJSON.keys().forEachRemaining( x -> { 
	    		try {
				String key = x.toString();
				String menuItem = menuJSON.getJSONObject(key).getString("desc");
	    			menu.put(x.toString(), menuItem );
			} catch (JSONException e) {
				e.printStackTrace();
			} 
	    	});
	    
		return menu;
    }
	
	@RequestMapping(value="/getCredentials", method=RequestMethod.GET, produces = { MediaType.APPLICATION_JSON_VALUE})
    public HashMap<String, String> getWhovilleCredentials() {
		
		String urlString = whovilleUrl + whovilleApiUri + whovilleCredentialUri;
	    HashMap<String, String> credentials = new HashMap<String,String>();
	    JSONObject credentialsJSON = httpGetObject(urlString, "", false);
	    
	    try {
			credentials.put("name",credentialsJSON.getString("name"));
			credentials.put("platform",credentialsJSON.getString("platform"));
	    } catch (JSONException e) {
			e.printStackTrace();
		}
	    	
		return credentials;
    }
	
	@RequestMapping(value="/deployPackage", method=RequestMethod.GET, produces = { MediaType.APPLICATION_JSON_VALUE})
    public JSONObject goWhovilleDeployPackage(@RequestParam(value="clusterType") String clusterType) {
		String urlString = whovilleUrl + whovilleApiUri + whovilleDeployPackagUri + "?clusterType=" + clusterType;
	    JSONObject result = httpGetObject(urlString, "", false);
		
		return result;
	}
	
	@RequestMapping(value="/refreshAllClusters", method=RequestMethod.GET, produces = { MediaType.APPLICATION_JSON_VALUE})
    private HashMap<String, Object> getClusterStatus() {
		String urlString = whovilleUrl + whovilleApiUri + whovilleStacksUri;
	    HashMap<String, Object> clusters = new HashMap<String,Object>();
	    JSONArray clustersJSON = httpGetArray(urlString, "");
	    LOG.info("Clusters: " + clustersJSON);
	    
	    for(int i=0;i<clustersJSON.length();i++){
	    		HashMap<String, Object> cluster = new HashMap<String,Object>();
	    		String clusterType = null;
	    		boolean isDps = false;
	    		boolean isSharedServices = false;
	    		
	    		try {
		    		LOG.info(clustersJSON.getJSONObject(i).toString());
	    			String blueprintName = clustersJSON.getJSONObject(i).getJSONObject("cluster").getJSONObject("blueprint").getString("name");
	    			clusterType = blueprintName;
	    			if(clusterType != null){
	    				isSharedServices = clustersJSON.getJSONObject(i).getJSONObject("userDefinedTags").getBoolean("datalake");
	    				isDps = clustersJSON.getJSONObject(i).getJSONObject("userDefinedTags").getBoolean("dps");
	    				
	    				String clusterId = clustersJSON.getJSONObject(i).getString("id");
	    				cluster.put("clusterId", clusterId);
	    			
	    				String clusterName = clustersJSON.getJSONObject(i).getString("name");
	    				cluster.put("clusterName", clusterName);
	    			
	    				String platform = clustersJSON.getJSONObject(i).getString("cloudPlatform");
	    				cluster.put("platform", platform);
	    			
	    				cluster.put("clusterType", clusterType);
	    				cluster.put("templateName",clustersJSON.getJSONObject(i).getJSONArray("instanceGroups").getJSONObject(0).getJSONObject("template").getString("instanceType"));
	    			
	    				String ambariServerIp = clustersJSON.getJSONObject(i).getJSONObject("cluster").getString("ambariServerIp");
	    				ambariServerIp = (ambariServerIp == null) ? "PENDING" : ambariServerIp;
	    				cluster.put("clusterAmbariIp", ambariServerIp);
	    				
	    				HashMap<String, String> gateway = new HashMap<String,String>();
	    				boolean isKnoxTopologyNull = clustersJSON.getJSONObject(i).getJSONObject("cluster").isNull("gateway"); 
	    				String topologyName = null;
	    				if(!isKnoxTopologyNull) {
	    					topologyName = clustersJSON.getJSONObject(i).getJSONObject("cluster").getJSONObject("gateway").getJSONArray("topologies").getJSONObject(0).getString("topologyName");
	    					JSONArray gatewayJSON = (topologyName != null) ? clustersJSON.getJSONObject(i).getJSONObject("cluster").getJSONObject("clusterExposedServicesForTopologies").getJSONArray(topologyName) : null;
		    				
		    				for(int j=0; j<gatewayJSON.length(); j++) {
		    					gateway.put(gatewayJSON.getJSONObject(j).getString("displayName"), gatewayJSON.getJSONObject(j).getString("serviceUrl"));
		    				}
	    				}

	    				ambariServerIp = (ambariServerIp == null) ? "PENDING" : ambariServerIp;
	    				cluster.put("clusterAmbariIp", ambariServerIp);
	    				
	    				if(isDps) { 
	    					dpsHost = ambariServerIp;
	    					dpsUrl = "https://" + dpsHost;
	    				}
	    				
	    				String clusterStatus = clustersJSON.getJSONObject(i).getJSONObject("cluster").getString("status");
	    				if(clusterStatus.equalsIgnoreCase("STOPPED") || clusterStatus.equalsIgnoreCase("DELETE_IN_PROGRESS")){
	    				clusterStatus = clustersJSON.getJSONObject(i).getString("status");
	    				}else if(ambariServerIp.equalsIgnoreCase("PENDING")){
	    					clusterStatus = clustersJSON.getJSONObject(i).getString("statusReason");
	    					if(clusterStatus.equalsIgnoreCase(""))
	    						clusterStatus = clustersJSON.getJSONObject(i).getString("status");
	    				}else{ 
	    					clusterStatus = clustersJSON.getJSONObject(i).getString("statusReason");
	    					if(clusterStatus.equalsIgnoreCase("") || clusterStatus.equalsIgnoreCase("Cluster creation finished."))
	    						clusterStatus = clustersJSON.getJSONObject(i).getString("status");
	    					//clusterStatus = getLastAmbariTask(ambariServerIp, clusterName);
	    				}
	    				
	    				cluster.put("clusterStatus", clusterStatus);
	    				cluster.put("gateway", gateway);
	    				cluster.put("isSharedServices", isSharedServices);
	    				cluster.put("isDps", isDps);
	    				clusters.put(clusterId, cluster);
	    			}
	    		} catch (JSONException e) {
	    			e.printStackTrace();
	    		} 
	    }
	    
	    urlString = whovilleUrl + whovilleApiUri + whovilleCBUri;
	    try {
	    		JSONArray cbJSON = httpGetArray(urlString, "");
			clusters.put("cbIp", cbJSON.get(0).toString());
		} catch (JSONException e) {
			e.printStackTrace();
		}
	    
	    return clusters;
    }

	private String getLastAmbariTask(String ambariIp, String clusterName){
		String urlString = "http://"+ambariIp+":8080/api/v1/clusters/"+clusterName+"/requests";
		String basicAuth = "Basic " + new String(Base64.encodeBase64("admin:admin".getBytes()));
		String currentTask = null;
		int itemsLength;
		try {
			JSONObject requestsJSON = httpGetObject(urlString, basicAuth, false);
			if(requestsJSON==null){
				return "Ambari conncetion timed out...";
			}	
			itemsLength = requestsJSON.getJSONArray("items").length();
			urlString = requestsJSON.getJSONArray("items").getJSONObject(itemsLength-1).getString("href");
			JSONObject requestJSON = httpGetObject(urlString, basicAuth, false);
			currentTask = requestJSON.getJSONObject("Requests").getString("request_context");
		} catch (JSONException e) {
			LOG.error("Connection timed out: " + urlString);
		}
		
		return currentTask;
	}
	
	private String getAmbariClusterService(String ambariIp, String clusterName, String serviceName){
		String urlString = "http://"+ambariIp+":8080/api/v1/clusters/"+clusterName+"/services/"+serviceName;
		String basicAuth = "Basic " + new String(Base64.encodeBase64((dpsAdminUserName + ":" + dpsAdminPassword).getBytes()));
				
		JSONObject service = httpGetObject(urlString, basicAuth, true);
		return null;
	}
	
    @RequestMapping(value="/search", produces = { MediaType.APPLICATION_JSON_VALUE})
    public ResponseEntity<List<String>> search(@RequestParam(value="term") String text) {
    	
    	List<String> searchResults = new ArrayList<String>();

    	Lists.newArrayList("cat","mouse","dog");
    	LOG.trace(text);

    	for (String name: Lists.newArrayList("cat","mouse","dog") ) {
    		if (name.toLowerCase().contains(text.toLowerCase())) {
	    		LOG.debug("match: "+ name);
	    		searchResults.add(name);
    		}
    	}
    	
    	if (!searchResults.isEmpty()) {
    		return new ResponseEntity<List<String>>(searchResults, HttpStatus.OK);
    	}
    	else {
    		return new ResponseEntity<List<String>>(searchResults, HttpStatus.BAD_REQUEST);
    	}	
    }
    
    @SuppressWarnings("unchecked")
   	@RequestMapping(value="/getDssEntity", method=RequestMethod.GET, produces = { MediaType.APPLICATION_JSON_VALUE})
    private HashMap<String, Object> getDssEntity(
    	@RequestParam(value="collectionId") String collectionId, 
    	@RequestParam(value="assetGuid") String assetGuid) {
       	HashMap<String, Object> entities = new HashMap<String, Object>();
       	ObjectMapper mapper = new ObjectMapper();
       	
     	String token = getDpsToken(dpsUrl+dps_auth_uri).get(0);
     	String assetClusterId = null; 
     	
     	LOG.info("+++++++++++++ " + dpsUrl+dss_dataset_uri+"/"+collectionId);
     	LOG.info("+++++++++++++ " + dpsUrl+dss_dataset_uri+"/"+collectionId+"/assets?queryName=&offset=0&limit=20");
     	try {
     		String datasetCluster = httpGetDpsObject(dpsUrl+dss_dataset_uri+"/"+collectionId, token).getString("cluster");
     		JSONArray assets = httpGetDpsObject(dpsUrl+dss_dataset_uri+"/"+collectionId+"/assets?queryName=&offset=0&limit=20", token).getJSONArray("assets");
     	
     		for(int i=0; i < assets.length(); i++) { 
				if(assets.getJSONObject(i).getString("guid").equalsIgnoreCase(assetGuid)) {
					assetClusterId = assets.getJSONObject(i).getString("clusterId");
				}
     		}
     	
     		JSONObject asset = httpGetDpsObject(dpsUrl+dss_assets_uri+"/"+assetClusterId+"/"+assetGuid, token);
     		LOG.info("+++++++++++++ " + asset);

     		entities = mapper.readValue(asset.toString(), HashMap.class);
     		entities.put("clusterName", datasetCluster);
     	} catch (JSONException e) {
     		e.printStackTrace();
     	} catch (JsonParseException e) {
			e.printStackTrace();
		} catch (JsonMappingException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
     	
       	return entities;
    }
    
    private Map<String, Object> getDssCollectionsTree(String token) throws JSONException{
		List<Object> collectionList = new ArrayList<Object>();
		
		JSONArray collections = httpGetDpsArray(dpsUrl+dss_collections_uri, token);
		LOG.info("+++++++++++++ " + collections);
		for(int i=0; i < collections.length(); i++) {
			Map<String, Object> collectionMap = new HashMap<String, Object>();
			List<Object> assetList = new ArrayList<Object>();
			String collectionId = collections.getJSONObject(i).getJSONObject("dataset").getString("id");
			String collectionName = collections.getJSONObject(i).getJSONObject("dataset").getString("name");
			String collectionClusterId = collections.getJSONObject(i).getString("cluster");
			
			collectionMap.put("id", collectionId);
			collectionMap.put("text", collectionName);
			collectionMap.put("icon", "fa fa-database");
			collectionMap.put("clusterId", collectionClusterId);
		
			LOG.info("++++++++++++++ Collection: " + collectionName);
			//JSONArray assets = httpGetArray(dps_url+dss_assets_uri + "/" + collectionId + "/assets?queryName&offset=0&limit=100", token);
			JSONArray assets = httpGetDpsObject(dpsUrl+dss_dataset_uri + "/" + collectionId + "/assets?queryName&offset=0&limit=100", token).getJSONArray("assets");
			for(int j = 0; j < assets.length(); j++) {
				Map<String, Object> asset = new HashMap<String, Object>();
				JSONObject assetJSON = assets.getJSONObject(j);
				String assetId = assetJSON.getString("id");
				String assetName = assetJSON.getString("assetName");
				String assetFQN = assetJSON.getJSONObject("assetProperties").getString("qualifiedName");
				String assetGuid = assetJSON.getString("guid");
				asset.put("id", assetFQN+"*"+assetId+"*"+assetGuid+"*"+collectionId);
				asset.put("text", assetName);
				asset.put("icon", "fa fa-table");
				asset.put("clusterId", collectionClusterId);
				LOG.info("+++++++++++++ AssetId: " + assetId + " AssetName: " + assetName + " GUID: " + assetGuid + " collectionId:" + collectionId);
				assetList.add(asset);
			}
			collectionMap.put("children", assetList);
			collectionList.add(collectionMap);
		}
		
		Map<String, Object> core = new HashMap<String, Object>();
		Map<String, Object> data = new HashMap<String, Object>();
		
		data.put("data", collectionList);
		core.put("core", data);
		LOG.info("***************** " + core);
		
		return core;
	}
    
    private JSONObject httpGetDpsObject(String urlString, String token) {
	    JSONObject response = null;

		try {
			URL url = new URL (urlString);
			HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
			connection.setRequestMethod("GET");
			connection.setDoOutput(true);            
			connection.setRequestProperty  ("Cookie", token);
			InputStream content = (InputStream)connection.getInputStream();
			BufferedReader rd = new BufferedReader(new InputStreamReader(content, Charset.forName("UTF-8")));
	      	String jsonText = readAll(rd);
	      	response = new JSONObject(jsonText);
		} catch(Exception e) {
			e.printStackTrace();
		}
		return response;
    }
    
    private JSONArray httpGetDpsArray(String urlString, String token) {
	    JSONArray response = null;
	    
		try {
			URL url = new URL (urlString);
			HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
			connection.setRequestMethod("GET");
			connection.setDoOutput(true);            
			connection.setRequestProperty  ("Cookie", token);
			InputStream content = (InputStream)connection.getInputStream();
			BufferedReader rd = new BufferedReader(new InputStreamReader(content, Charset.forName("UTF-8")));
	      	String jsonText = readAll(rd);
	      	response = new JSONArray(jsonText);
		} catch(Exception e) {
			e.printStackTrace();
		}
		return response;
    }
    	
    @RequestMapping(value="/getFileTree", method=RequestMethod.GET, produces = { MediaType.APPLICATION_JSON_VALUE})
    public HashMap<String, Object> getFileTree() {   
	    	HashMap<String, Object> coreHm = new HashMap<String, Object>();
	    	HashMap<String, Object> dataHm = new HashMap<String, Object>();
	    	List<Object> data = new ArrayList<Object>();
	
	    	dataHm.put("data", data);
	    	coreHm.put("core", dataHm);   	
	    	if(dpsUrl != null) {    	
		    	String token = getDpsToken(dpsUrl+dps_auth_uri).get(0);
		    	
		    	try {
				coreHm = (HashMap<String, Object>) getDssCollectionsTree(token);
			} catch (JSONException e) {
				e.printStackTrace();
			}
	    	}
		return coreHm;
    }
    
	private List<String> getDpsToken(String urlString) {
	    	List<String> token = null;

	    	String basicAuth = "Basic " + new String(Base64.encodeBase64((dpsAdminUserName + ":" + dpsAdminPassword).getBytes()));
	    	try {
	    		URL url = new URL (urlString+dpsUrl);
	    		HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();
	    		connection.setRequestMethod("POST");
	    		connection.setDoOutput(true);
	    		connection.setInstanceFollowRedirects(false);
	    		connection.setRequestProperty  ("Authorization", basicAuth);
	    		//connection.setRequestProperty("Content-Type", "application/json");
	    		OutputStream os = connection.getOutputStream();
	    		//os.write(payload.getBytes());
	    		os.flush();
	    		
	    		if (connection.getResponseCode() > 308) {
	    			throw new RuntimeException("Failed : HTTP error code : "+ connection.getResponseCode() + ", expected 303 redirect...");
	    		}else{
	          	token = connection.getHeaderFields().get("Set-Cookie");
	    		}
	    	} catch(Exception e) {
	    		e.printStackTrace();
	    	}
	    	return token;
	}
 
    private JSONObject httpGetObject(String urlString, String authorizationString, boolean secure) {
    		JSONObject response = null;
    		InputStream content = null;
    	
    		try {
            URL url = new URL (urlString);
            HttpURLConnection connection = (secure) ? connection = (HttpsURLConnection) url.openConnection() : (HttpURLConnection) url.openConnection();	
            connection.setRequestMethod("GET");
            connection.setDoOutput(true);
            connection.setConnectTimeout(3000);
            connection.setRequestProperty  ("Authorization", authorizationString);
            content = (InputStream)connection.getInputStream();            
            BufferedReader rd = new BufferedReader(new InputStreamReader(content, Charset.forName("UTF-8")));
            String jsonText = readAll(rd);
            response = new JSONObject(jsonText);
	    } catch(Exception e) {
	        LOG.error("Connection timed out: "+urlString);
	    }
    		
		return response;
    }
    
    private JSONArray httpGetArray(String urlString, String authorizationString) {
    		JSONArray response = null;
    		
    		try {
            URL url = new URL (urlString);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setDoOutput(true);
            connection.setRequestProperty  ("Authorization", authorizationString);
            InputStream content = (InputStream)connection.getInputStream();
            BufferedReader rd = new BufferedReader(new InputStreamReader(content, Charset.forName("UTF-8")));
  	      	String jsonText = readAll(rd);
  	      	response = new JSONArray(jsonText);
        } catch (MalformedURLException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (JSONException e) {
			e.printStackTrace();
		} finally{}

		return response;
    }
	
	private static String getToken(String urlString, String credentials) {
    	String response = null;
    	
    	try {
            URL url = new URL (urlString);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setDoOutput(true);
            connection.setInstanceFollowRedirects(false);
            connection.setRequestMethod("GET");
            connection.setRequestProperty("Accept","application/x-www-form-urlencoded");
            connection.setRequestProperty("Content-Type","application/x-www-form-urlencoded");
            
            OutputStream os = connection.getOutputStream();
    			os.write(credentials.getBytes());
    			os.flush();
    		
            if (connection.getResponseCode() != 302) {
    			throw new RuntimeException("Failed : HTTP error code : "+ connection.getResponseCode());
    		}
            
        //System.out.println(connection.getHeaderFields());
    		String[] responseArray = connection.getHeaderField("Location").split("access_token=")[1].split("&");
    		System.out.println(responseArray[0]);
    		//System.out.println(responseArray[1].split("=")[1]);
            response = responseArray[0];
        } catch(Exception e) {
            e.printStackTrace();
        }
		return response;
    }
	
	private JSONObject httpGetObject(String urlString, boolean secure) {
		JSONObject response = null;
		
		try {
			URL url = new URL (urlString);
			HttpURLConnection connection = (secure) ? connection = (HttpsURLConnection) url.openConnection() : (HttpURLConnection) url.openConnection();
			connection.setRequestMethod("GET");
    		    connection.setDoOutput(true);
    		    connection.setRequestProperty  ("Authorization", "Bearer " + oAuthToken);
    		    connection.setRequestProperty  ("Accept", "application/json");
    		    if (connection.getResponseCode() <= 202) {
            		InputStream content = (InputStream)connection.getInputStream();
            		BufferedReader rd = new BufferedReader(new InputStreamReader(content, Charset.forName("UTF-8")));
            		String jsonText = readAll(rd);
            		response = new JSONObject(jsonText);
    		  	} else if (connection.getResponseCode() > 202) {	
    		  		response = new JSONObject("{\"input\":\""+urlString+"\",\"result\":\"not-found\"}");
    		  	}
		} catch (IOException e) {
				e.printStackTrace();
		} catch (JSONException e) {
				e.printStackTrace();
		}
		return response;
	}
	
	private String readAll(Reader rd) throws IOException {
	    StringBuilder sb = new StringBuilder();
	    int cp;
	    while ((cp = rd.read()) != -1) {
	      sb.append((char) cp);
	    }
	    return sb.toString();
	}
	
	private void initializeTrustManager(){
		TrustManager[] trustAllCerts = new TrustManager[]{
			new X509TrustManager() {
				public java.security.cert.X509Certificate[] getAcceptedIssuers() {
					return null;
				}
				public void checkClientTrusted(
					java.security.cert.X509Certificate[] certs, String authType) {
				}
				public void checkServerTrusted(
					java.security.cert.X509Certificate[] certs, String authType) {
				}
			}
		};

		//Install the all-trusting trust manager
		try {
			SSLContext sc = SSLContext.getInstance("SSL");
			sc.init(null, trustAllCerts, new java.security.SecureRandom());
			HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

			HostnameVerifier allHostsValid = new HostnameVerifier() {
				public boolean verify(String hostname, SSLSession session) {
					return true;
				}
		    };
			HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
			HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}