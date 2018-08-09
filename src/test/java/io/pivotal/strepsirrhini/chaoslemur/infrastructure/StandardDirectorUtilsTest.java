/*
 * Copyright 2014-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package io.pivotal.strepsirrhini.chaoslemur.infrastructure;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.Test;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.web.client.RestTemplate;

public final class StandardDirectorUtilsTest {

    private final Map<String, String> deployment = Collections.singletonMap("name", "test-deployment");

    private final RestTemplate restTemplate = mock(RestTemplate.class);

    private final URI root = URI.create("http://localhost");
    
    private String host ="host";
	private String username ="user'";
	private String password ="password";
	

    private final StandardDirectorUtils directorUtils = new StandardDirectorUtils(this.restTemplate, this.root,host,username,password,null);
    	private final Map<String, String> vm = Collections.singletonMap("cid", "test-cid");

//    @Test
//    public void constructor() throws GeneralSecurityException {
//        new StandardDirectorUtils("test-host", "test-username", "test-password", new HashSet<>());
//    }

    @Test
    public void getDeployments() {
        when(this.restTemplate.getForObject(URI.create("http://localhost/deployments"), List.class))
            .thenReturn(Arrays.asList(this.deployment));

        Set<String> expected = new HashSet<>();
        expected.add("test-deployment");

        assertEquals(expected, this.directorUtils.getDeployments());
    }

  

	@Test
    public void getVirtualMachines() {
        Set<Map<String, String>> expected = new HashSet<>();
        expected.add(this.vm);

        when(this.restTemplate.getForObject(URI.create("http://localhost/deployments/test-deployment/vms"), Set.class))
            .thenReturn(expected);

        assertEquals(expected, this.directorUtils.getVirtualMachines("test-deployment"));
    }

}