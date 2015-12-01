# Quick usage tour #

## Download the library here ##

http://code.google.com/p/java-google-safe-browsing/source/browse/target/JavaGSB.jar

## Import them in your Java file ##
```
import com.gsbcrawler.GSBCrawler;
import com.gsbanalyzer.GSBAnalyzer;
import com.gsbanalyzer.gsb.models.GSBInfectedUrl;
```

## Instantiate classes and use them ##

### Update the database ###
```
GSBCrawler gsbCrawler = new GSBCrawler("YOUR_GSB_KEY", "YOUR_DB_PREFIX", "YOUR_PATH", "jdbc:mysql://localhost/gsb", "DB_LOGIN", "DB_PASSWORD");
int timeToWait = gsbCrawler.updateDB();
System.out.println(timeToWait+" to wait before next update");
		
```

The crawler will create tables if they don't exists.
The crawler has create two file to store the timestamp of the next possible update. You can choose the path in the constructor.

You need to **execute the update many times** to download all the Google's datas. It can be take a long time.

### Check a list of domains ###
```
List<String> domainsToCheck = new ArrayList<String>();
domainsToCheck.add("ianfette.org");
GSBAnalyzer gsbWrapper = new GSBAnalyzer("YOUR_GSB_KEY","http://safebrowsing.clients.google.com/safebrowsing","YOUR_DB_PREFIX", "jdbc:mysql://localhost/gsb","DB_LOGIN","DB_PASSWORD");
List<GSBInfectedUrl> gsbDirtyDomains = gsbWrapper.analyzeWithGSB(domainsToCheck);
for(GSBInfectedUrl gsbDirtyDomain : gsbDirtyDomains){
    System.out.println(gsbDirtyDomain);
}
```

A GSBInfectedUrl is verified if the server of GSB knows the domain.