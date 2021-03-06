/*
 * Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License
 * is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
 * or implied. See the License for the specific language governing permissions and limitations under
 * the License.
 */
package monasca.common.middleware;


import org.apache.http.client.ClientProtocolException;
import org.apache.thrift.TException;

/**
 * A client that can communicate to an authentication server for authentication.
 *
 * @author liemmn
 */
public interface AuthClient {

  public String validateTokenForServiceEndpointV3(String token) throws TException, ClientProtocolException;
}
