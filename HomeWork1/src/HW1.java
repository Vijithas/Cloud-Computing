import com.vmware.vim25.*;
import java.util.*;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import java.io.BufferedWriter;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.text.SimpleDateFormat;

import javax.xml.ws.BindingProvider;
import javax.xml.ws.soap.SOAPFaultException;
import java.io.IOException;

public class HW1 {
	
	static ManagedObjectReference SVC_INST_REF = new ManagedObjectReference();
	static ManagedObjectReference viewManager;
	static ManagedObjectReference perfManager;
	static ManagedObjectReference propertyCollector;
	static VimService vimService;
	static VimPortType vimPort;
	static ServiceContent serviceContent;
	static String serverName;
	static String virtualMachineName;
	static String userName;
	static String password;
	static String url;
	static String vmStatFile;
	static String serverStatFile;
	
	static List<ObjectContent> getAttributesAllObjects(ManagedObjectReference propCollectorRef,
	            List<PropertyFilterSpec> listpfs) {

	        RetrieveOptions retrievePropObjects = new RetrieveOptions();

	        List<ObjectContent> listobjcontent = new ArrayList<ObjectContent>();

	        try {
	            RetrieveResult retrieveResults =
	                    vimPort.retrievePropertiesEx(propCollectorRef, listpfs,
	                            retrievePropObjects);
	            if (retrieveResults != null && retrieveResults.getObjects() != null
	                    && !retrieveResults.getObjects().isEmpty()) {
	                listobjcontent.addAll(retrieveResults.getObjects());
	            }
	            String token = null;
	            if (retrieveResults != null && retrieveResults.getToken() != null) {
	                token = retrieveResults.getToken();
	            }
	            while (token != null && !token.isEmpty()) {
	                retrieveResults =
	                        vimPort.continueRetrievePropertiesEx(propCollectorRef, token);
	                token = null;
	                if (retrieveResults != null) {
	                    token = retrieveResults.getToken();
	                    if (retrieveResults.getObjects() != null && !retrieveResults.getObjects().isEmpty()) {
	                        listobjcontent.addAll(retrieveResults.getObjects());
	                    }
	                }
	            }
	        }  catch (SOAPFaultException sfe) {
	            printSoapFaultException(sfe);
	        } catch (Exception e) {
	            System.out.println(" : Failed Getting Contents");
	            e.printStackTrace();
	        }

	        return listobjcontent;
	    }
	
/* Create a traversal specification that starts from the 'root' 			
*  objects and traverses the inventory tree to get to the VirtualMachines 
*  Build the traversal specification in the bottom up fashion  			
*  This is mainly required to traverse and get the VM in a VApp 			
*/

	public static TraversalSpec getVMTraversalSpec() {
        
        TraversalSpec vAppToVM = new TraversalSpec();
		vAppToVM.setName("vAppToVM");
		vAppToVM.setType("VirtualApp");
		vAppToVM.setPath("vm");
		
/*Traversal specification for VApp to VApp*/
        TraversalSpec vAppToVApp = new TraversalSpec();
        vAppToVApp.setName("vAppToVApp");
		vAppToVApp.setPath("resourcePool");
        vAppToVApp.setType("VirtualApp");
        
        List<SelectionSpec> list = new ArrayList<SelectionSpec>();
        
		SelectionSpec spec1 = new SelectionSpec();
        spec1.setName("vAppToVApp");
        
		SelectionSpec spec2 = new SelectionSpec();
        spec2.setName("vAppToVM");
       
        list.add(spec1);
        list.add(spec2);
        vAppToVApp.getSelectSet().addAll(list);
               
/* This SelectionSpec is used for recursion for Folder recursion */

        SelectionSpec visitFolders = new SelectionSpec();
        visitFolders.setName("VisitFolders");

/* Traversal to get to the vmFolder from DataCenter */
  
        TraversalSpec dataCenterToVMFolder = new TraversalSpec();
		dataCenterToVMFolder.setName("DataCenterToVMFolder");
		dataCenterToVMFolder.setType("Datacenter");
		dataCenterToVMFolder.setPath("vmFolder");
		dataCenterToVMFolder.setSkip(false);
		dataCenterToVMFolder.getSelectSet().add(visitFolders);
        
        
		TraversalSpec tSpec = new TraversalSpec();
		tSpec.setName("VisitFolders");
		tSpec.setPath("childEntity");
		tSpec.setType("Folder");
		tSpec.setSkip(false);
		
		List<SelectionSpec> sSpecArr = new ArrayList<SelectionSpec>();
		sSpecArr.add(visitFolders);
		sSpecArr.add(vAppToVApp);
		sSpecArr.add(dataCenterToVMFolder);
		sSpecArr.add(vAppToVM);
		tSpec.getSelectSet().addAll(sSpecArr);
		 
		return tSpec;
	}
	
	 static void printSoapFaultException(SOAPFaultException sfe) {
	        System.out.println("SOAP Fault -");
	        if (sfe.getFault().hasDetail()) {
	            System.out.println(sfe.getFault().getDetail().getFirstChild()
	                    .getLocalName());
	        }
	        if (sfe.getFault().getFaultString() != null) {
	            System.out.println("\n Exception Message: " + sfe.getFault().getFaultString());
	        }
	    }
	
	/*
	 * This function checks the server/virtual machine connections
	 * 	
	 */	
	 private static void getInfo(String name, String vmOrServer, String fileName,ManagedObjectReference vmManagedObjectRef){
			
			// fetch the ManagedObjectReference of specified VM or Server

			String vmAttributes[] = new String[] {
					"mem.consumed.AVERAGE",
					"cpu.usagemhz.AVERAGE"
			};
			
			String serverAttributes[] = new String[] {
					"mem.consumed.AVERAGE",
					"cpu.usagemhz.AVERAGE",
					"net.received.AVERAGE"
			};
			
			try{
				if(vmManagedObjectRef != null){
					
					System.out.println("\n\n"+"" + vmOrServer + " : "  + name + " available"+"\n\n");
					
					List<PerfCounterInfo> cInfo = getPerfCounters(serviceContent.getPerfManager());
					Map<String, Integer> counterIDMap =
		                    new HashMap<String, Integer>();
					Map<Integer, PerfCounterInfo> counterInfoMap =
		                    new HashMap<Integer, PerfCounterInfo>();
		            for (PerfCounterInfo perfInfo : cInfo){
		            	String counterGroup = perfInfo.getGroupInfo().getKey();
		    			String counterName = perfInfo.getNameInfo().getKey();
		    			String counterRollupType = perfInfo.getRollupType().toString();
		    			String fullCounterName = counterGroup + "." + counterName + "." + counterRollupType;
		    			Integer counterID = new Integer(perfInfo.getKey());
		    			counterIDMap.put(fullCounterName, counterID);	    			
		    			counterInfoMap.put(counterID, perfInfo);
		            }
		            
		            List<PerfMetricId> mMetrics = new ArrayList<PerfMetricId>();
		            if(vmOrServer.equals("VM")){
		            	for(String dataToCollect : vmAttributes){
			            	PerfMetricId metricId = new PerfMetricId();
			    	        metricId.setCounterId(counterIDMap.get(dataToCollect));
			    	        metricId.setInstance("*");
			    	        mMetrics.add(metricId);
			            }
		            }
		            else{
		            	// collect SERVER metrics
		            	for(String dataToCollect : serverAttributes){
			            	PerfMetricId metricId = new PerfMetricId();
			    	        metricId.setCounterId(counterIDMap.get(dataToCollect));
			    	        metricId.setInstance("*");
			    	        mMetrics.add(metricId);
			            }
		            }	            
		            // start collecting performance and fill in fileName
		            performanceStats(perfManager, vmManagedObjectRef, mMetrics, counterInfoMap, fileName, vmOrServer);	            
				}
				else{
					System.out.println("\n The Virtual Machine is not Found");
					System.exit(0);
				}
			}
			catch(Exception e){
				System.out.println(" Connection Failed ");
				e.printStackTrace();
			}			
		}
	 

/* This function monitors the statistics or performance of the VM and the Server every 10 seconds */
	 
	 static void performanceStats(ManagedObjectReference pmRef,
			 ManagedObjectReference vmRef, List<PerfMetricId> mMetrics,
			 Map<Integer, PerfCounterInfo> counters,String file, String serverName) throws RuntimeFaultFaultMsg, InterruptedException {
		 
		 PerfQuerySpec pSpecs = new PerfQuerySpec();
		 pSpecs.setEntity(vmRef);
		 pSpecs.setMaxSample(new Integer(1));
		 pSpecs.getMetricId().addAll(mMetrics);
		 pSpecs.setIntervalId(new Integer(20));
		 pSpecs.setFormat("csv");

		 List<PerfQuerySpec> pSpec = new ArrayList<PerfQuerySpec>();
		 pSpec.add(pSpecs);
		 try{
			 String vmName = virtualMachineName;
			 PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(file,true)));
			 
			 if(serverName.equals("SERVER")){
				 vmName = serverName;
			 }
			pw.println("System Statistics " + serverName + ": " + vmName);
			pw.println();
			pw.close();	 
		 }
		 catch(Exception e){
			 e.printStackTrace();
		 }
		 while (true) {
			 List<PerfEntityMetricBase> listpemb = vimPort.queryPerf(pmRef, pSpec);
			 List<PerfEntityMetricBase> pValues = listpemb;
			 if (pValues != null) {
				 writeFileOutput(counters,file,serverName,pValues);
			 }
			 System.out.println("Pause for 10 seconds...");
			 Thread.sleep(10 * 1000);
		 }
	 }
	 
/* Function to write the Server and VM Statistics into a output file*/	 

	 private static void writeFileOutput(Map<Integer, PerfCounterInfo> counters,String fileName, String vmOrServer, List<PerfEntityMetricBase> pValues ){
	    		
	    	for(PerfEntityMetricBase perfValue : pValues){
	    		PerfEntityMetricCSV entityStatsCsv = (PerfEntityMetricCSV)perfValue;

				List<PerfMetricSeriesCSV> metricsValues = entityStatsCsv.getValue();
				if(metricsValues.isEmpty()) {
					System.out.println(" Error - Unable to reach virtual machine");
					System.exit(0);
				}				
				//String csvTimeInfoAboutStats = entityStatsCsv.getSampleInfoCSV();
				PrintWriter pw1;
				boolean cpuPrinted = false;
				boolean networkPrinted = false;
				for(PerfMetricSeriesCSV perfMetricCsv : metricsValues)	{
					
					PerfCounterInfo pci = counters.get(perfMetricCsv.getId().getCounterId());
					
					try {
						pw1 = new PrintWriter(new BufferedWriter(new FileWriter(fileName, true)));
						//java.util.Date date= new java.util.Date();
						String timeStamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new java.util.Date());
						if (pci.getGroupInfo().getKey().equals("cpu") && cpuPrinted == false) {
							cpuPrinted = true;
							pw1.print(pci.getGroupInfo().getKey().toUpperCase() + " usage in " + pci.getUnitInfo().getKey() + " with timestamp: "+ " (" + timeStamp +")");
							pw1.println(" : " + perfMetricCsv.getValue());
						} else if (pci.getGroupInfo().getKey().equals("mem")){
							int megabytes = Integer.parseInt(perfMetricCsv.getValue());
							megabytes = megabytes/1024;
							pw1.print("Usage of Memory in megaBytes" + " at time " + "(" + timeStamp + ")");
							pw1.println(" : " + megabytes + "\n");
							pw1.println();
						}
						else if(pci.getGroupInfo().getKey().equals("net") && vmOrServer.equals("SERVER") && networkPrinted == false){
							networkPrinted = true;
							int megabytes = Integer.parseInt(perfMetricCsv.getValue());
							megabytes = megabytes/1024;
							pw1.print("\n");
							pw1.println();
							pw1.print("Available Network Bandwidth " + " with timestamp " + "(" + timeStamp + ")");
							pw1.println(" : " + megabytes);
						}
						pw1.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
				
	    	}
	    }
	 
	 
	 private static void resultMapping(RetrieveResult results, Map<String, ManagedObjectReference> tgt2mor) {
			List<ObjectContent> oCont = (results != null) ? results.getObjects() : null;
			if (oCont != null) {
				for (ObjectContent objectContent : oCont) {
					ManagedObjectReference mrObj = objectContent.getObj();
					String entityNm = null;
					List<DynamicProperty> dpsAttribute = objectContent.getPropSet();
					if (dpsAttribute != null) {
						for (DynamicProperty dp : dpsAttribute) {
							entityNm = (String) dp.getVal();
						}
					}
					tgt2mor.put(entityNm, mrObj);
				}
			}
		}

/* Function to retreive performance stats*/
	 static List<PerfCounterInfo> getPerfCounters(ManagedObjectReference perfManager) {
	        List<PerfCounterInfo> pciArr = null;
	        try {
				
				// Creation of Object Specification
	            ObjectSpec objectSpec = new ObjectSpec();
	            objectSpec.setObj(perfManager);
	            List<ObjectSpec> objectSpecs = new ArrayList<ObjectSpec>();
	            objectSpecs.add(objectSpec);
				
	            // Creation of Property Specification
	            PropertySpec propertySpec = new PropertySpec();
	            propertySpec.setAll(Boolean.FALSE);
	            propertySpec.getPathSet().add("perfCounter");
	            propertySpec.setType("PerformanceManager");
	            List<PropertySpec> propertySpecs = new ArrayList<PropertySpec>();
	            propertySpecs.add(propertySpec);
            
	            PropertyFilterSpec propertyFilterSpec = new PropertyFilterSpec();
	            propertyFilterSpec.getPropSet().add(propertySpec);
	            propertyFilterSpec.getObjectSet().add(objectSpec);

	            List<PropertyFilterSpec> propertyFilterSpecs =
	                    new ArrayList<PropertyFilterSpec>();
	            propertyFilterSpecs.add(propertyFilterSpec);

	            List<PropertyFilterSpec> listpfs =
	                    new ArrayList<PropertyFilterSpec>(1);
	            listpfs.add(propertyFilterSpec);
	            List<ObjectContent> listobjcont =
	                    getAttributesAllObjects(serviceContent.getPropertyCollector(),listpfs);

	            if (listobjcont != null) {
	                for (ObjectContent oc : listobjcont) {
	                    List<DynamicProperty> dynamicProp = oc.getPropSet();
	                    if (dynamicProp != null) {
	                        for (DynamicProperty dp : dynamicProp) {
	                            List<PerfCounterInfo> pcinfolist =
	                                    ((ArrayOfPerfCounterInfo) dp.getVal())
	                                            .getPerfCounterInfo();
	                            pciArr = pcinfolist;
	                        }
	                    }
	                }
	            }
	        } catch (SOAPFaultException sfe) {
	            printSoapFaultException(sfe);
	        } catch (Exception e) {
	            e.printStackTrace();
	        }
	        return pciArr;
	    }
 
	
    public static ManagedObjectReference vmByVMname(
            final String virtualMachineName, final ManagedObjectReference propCollectorRef
    ) throws InvalidPropertyFaultMsg, RuntimeFaultFaultMsg {


        ManagedObjectReference retVal = null;
        ManagedObjectReference rootFolder = serviceContent.getRootFolder();
        TraversalSpec tSpec = getVMTraversalSpec();
        
        // Creating Property Spec
        PropertySpec propertySpec = new PropertySpec();
        propertySpec.setAll(Boolean.FALSE);
        propertySpec.getPathSet().add("name");
        propertySpec.setType("VirtualMachine");

        // Creating Object Spec
        ObjectSpec objectSpec = new ObjectSpec();
        objectSpec.setObj(rootFolder);
        objectSpec.setSkip(Boolean.TRUE);
        objectSpec.getSelectSet().add(tSpec);

         PropertyFilterSpec propertyFilterSpec = new PropertyFilterSpec();
        		propertyFilterSpec.getPropSet().add(propertySpec);
        		propertyFilterSpec.getObjectSet().add(objectSpec);

        List<PropertyFilterSpec> listpfs =
                new ArrayList<PropertyFilterSpec>(1);
        listpfs.add(propertyFilterSpec);

        RetrieveOptions options = new RetrieveOptions();
        List<ObjectContent> listobcont =
                vimPort.retrievePropertiesEx(propCollectorRef, listpfs, options).getObjects();

        if (listobcont != null) {
            for (ObjectContent oc : listobcont) {
                ManagedObjectReference mr = oc.getObj();
                String vmnm = null;
                List<DynamicProperty> dynamicProp = oc.getPropSet();
                if (dynamicProp != null) {
                    for (DynamicProperty dp : dynamicProp) {
                        vmnm = (String) dp.getVal();
                    }
                }
                if (vmnm != null && vmnm.equals(virtualMachineName)) {
                    retVal = mr;
                    break;
                }
            }
        }
        return retVal;
    }
    
    
    private static PropertyFilterSpec[] propFilSpecs(
			ManagedObjectReference container,
			String morefType,
			String... morefProperties
			) throws RuntimeFaultFaultMsg {

		ManagedObjectReference viewManager = serviceContent.getViewManager();
		ManagedObjectReference containerView =
				vimPort.createContainerView(viewManager, container,
						Arrays.asList(morefType), true);
		
		TraversalSpec tSpec = new TraversalSpec();
		tSpec.setName("view");
		tSpec.setPath("view");
		tSpec.setSkip(false);
		tSpec.setType("ContainerView");
		
		PropertySpec propSpec = new PropertySpec();
		propSpec.setAll(Boolean.FALSE);
		propSpec.setType(morefType);
		propSpec.getPathSet().addAll(Arrays.asList(morefProperties));
	
		
		ObjectSpec objSpec = new ObjectSpec();
		objSpec.setObj(containerView);
		objSpec.setSkip(Boolean.TRUE);
		objSpec.getSelectSet().add(tSpec);
		
		PropertyFilterSpec propFilterSpec1 = new PropertyFilterSpec();
		
		propFilterSpec1.getObjectSet().add(objSpec);
		propFilterSpec1.getPropSet().add(propSpec);
		
		return new PropertyFilterSpec[]{
				propFilterSpec1
		};
	}
  
    
    private static Map<String, ManagedObjectReference> inFolder(
			final ManagedObjectReference folder, final String morefType, final RetrieveOptions retrieveOptions
			) throws RuntimeFaultFaultMsg, InvalidPropertyFaultMsg {
		final PropertyFilterSpec[] propertyFilterSpecs = propFilSpecs(folder, morefType, "name");
		
		final ManagedObjectReference propertyCollector = serviceContent.getPropertyCollector();

		RetrieveResult results = vimPort.retrievePropertiesEx(
				propertyCollector,
				Arrays.asList(propertyFilterSpecs),
				retrieveOptions);

		final Map<String, ManagedObjectReference> tgtMoref =
				new HashMap<String, ManagedObjectReference>();
		while(results != null && !results.getObjects().isEmpty()) {
			resultMapping(results, tgtMoref);
			final String token = results.getToken();
			results = (token != null) ? vimPort.continueRetrievePropertiesEx(propertyCollector,token) : null;
		}

		return tgtMoref;
	}
	
	private static class TrustAllTrustManager implements javax.net.ssl.TrustManager,
	javax.net.ssl.X509TrustManager {
	 
	public java.security.cert.X509Certificate[] getAcceptedIssuers() {
	return null;
	}
	 
	public void checkServerTrusted(java.security.cert.X509Certificate[] certs,
	String authType)
	throws java.security.cert.CertificateException {
	return;
	}
	 
	public void checkClientTrusted(java.security.cert.X509Certificate[] certs,
	String authType)
	throws java.security.cert.CertificateException {
	return;
	}
	}
	
	public static void main(String[] args) {
		
		try {
			// URL and credentials for login
			serverName = "128.230.208.175";
			userName = "vsphere.local\\CloudComputing";
			password = "CSE612@2017";
			url = "https://128.230.247.56/sdk";
			vmStatFile = "VMStat.txt";
			serverStatFile="ServerStat.txt";
			virtualMachineName = "CloudComputing07";
			// Variables of the following types for access to the API methods
			// and to the vSphere inventory.
			// -- ManagedObjectReference for the ServiceInstance on the Server
			// -- VimService for access to the vSphere Web service
			// -- VimPortType for access to methods
			// -- ServiceContent for access to managed object services
					
 
			// A Host Name Verifier will automatically enable the connection and is invoked during a SSL handshake. 
			HostnameVerifier hostverify = new HostnameVerifier() {
			public boolean verify(String urlHostName, SSLSession session) {
			return true;
			}
			};
			// Trust Manager creation
			javax.net.ssl.TrustManager[] trustAllCerts = new javax.net.ssl.TrustManager[1];
			javax.net.ssl.TrustManager tm = new TrustAllTrustManager();
			trustAllCerts[0] = tm;
			 
			// SSL context creation
			javax.net.ssl.SSLContext sc = javax.net.ssl.SSLContext.getInstance("SSL");
			 
			// Session context creation
			javax.net.ssl.SSLSessionContext sslsc = sc.getServerSessionContext();
			 
			// Initialization of the contexts; the session context uses the trust manager.
			sslsc.setSessionTimeout(0);
			sc.init(null, trustAllCerts, null);
			 
			// Use the default socket factory to create the socket for the secure connection
			javax.net.ssl.HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
			// Set the default host name verifier to enable the connection.
			HttpsURLConnection.setDefaultHostnameVerifier(hostverify);
			 
			// Set up the manufactured managed object reference for the ServiceInstance
			SVC_INST_REF.setType("ServiceInstance");
			SVC_INST_REF.setValue("ServiceInstance");
			 
			// Create a VimService object to obtain a VimPort binding provider.
			// The BindingProvider provides access to the protocol fields
			// in request/response messages. Retrieve the request context
			// which will be used for processing message requests.
			vimService = new VimService();
			vimPort = vimService.getVimPort();
			Map<String, Object> ctxt = ((BindingProvider) vimPort).getRequestContext();
			 
			// Store the Server URL in the request context and specify true
			// to maintain the connection between the client and server.
			// The client API will include the Server's HTTP cookie in its
			// requests to maintain the session. If you do not set this to true,
			// the Server will start a new session with each request.
			ctxt.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, url);
			ctxt.put(BindingProvider.SESSION_MAINTAIN_PROPERTY, true);
			 
			// Retrieve the ServiceContent object and login
			serviceContent = vimPort.retrieveServiceContent(SVC_INST_REF);
			vimPort.login(serviceContent.getSessionManager(),
			userName,
			password,
			null);
			
	
			viewManager = serviceContent.getViewManager();
			propertyCollector = serviceContent.getPropertyCollector();
			perfManager = serviceContent.getPerfManager();
			
			final ManagedObjectReference managedObjectreference = vmByVMname(virtualMachineName,propertyCollector);
			RetrieveOptions retrieve = new RetrieveOptions();
			Map<String, ManagedObjectReference> map = inFolder(serviceContent.getRootFolder(),"HostSystem",retrieve);
			final ManagedObjectReference serMap = map.get(serverName);
			
			Thread vmStats = new Thread(new Runnable(){
				public void run(){
					getInfo(virtualMachineName,"VM",vmStatFile,managedObjectreference);
				}
			});
			vmStats.start();
			
			Thread serverStats = new Thread(new Runnable(){
				public void run(){
					getInfo(serverName,"SERVER",serverStatFile,serMap);
				}
			});
			serverStats.start();
	
			vmStats.join();
			serverStats.join();
			
			vimPort.logout(serviceContent.getSessionManager());
			}
		catch (Exception e) {
			System.out.println(" Connection Failed ");
			e.printStackTrace();
			}

	}

}
