const { CRUD_PERMISSION } = require('./constant')
const url = require("url");

/**
 * 
 * 
  apikeys: {
 	[$key]: {
 		domains: [],
 		collection: {
 			[$collection]: ['create', 'read', 'update', 'delete']
 		},
 		roles: ['admin', ...]
 	}
  },
  
  roles: {
  	[$role]: {
  		collection: {
  			[$collection]: ['create', 'read', 'update', 'delete']
  		}
  	},
  }
 	
 }
 */

class CoCreatePermission {
	constructor() {
		this.permissions = new Map();
	}
	
	setPermissionObject(apikey, permission) {
		this.permissions.set(apikey, permission)
	}
	
	hasPermission(key) {
		return this.permissions.has(key)
	}
	
	async getRolesByKey(key, organization_id, type) {
		if (this.permissions.get(key)) {
			return this.permissions.get(key)
		} else {
			
			//. get permissions from db
			//. we should add the code to get permissions from db by apikey
			//. Notes: now we are using mock data
			//. mockData = /** PermissionData **/
			//. how do we query the permissiondata... what is the order of operation? 
				//  apikey=> domains=> collections => roles = true/false response
				//. if user_id/token => domain => colections => roles = true
			//. merget roles collection and permission collection
			
			let permission = await this.getPermissionObject(key, organization_id, type);

			this.permissions.set(key, permission)
			return permission
		}
	}
	
	//. overrride function
	getParameters(action, data) {
		return {};
		// const { apiKey, organization_id, collection } = data;
		// return {
		// 	apikey: apiKey,
		// 	organization_id,
		// 	type: 'readDocument || getStripe || login',
		// 	plugin: 'messages || strip || facebook',
		//  collection: 'test || users'
		// }
		
	}
	
	//. overrride function
	async getPermissionObject(key, organization_id, type) {
		return null;
	}
	
	async check(action, data, req, user_id) {
		const host = this.getHost(req.headers)
		const { apikey, ...paramData} = this.getParameters(action, data)
		// const { apikey, organization_id, key, key_value, type } = this.getParameters(action, data)
		paramData.host = host;
		//. check user
		let status = false
		status = await this.checkPermissionObject({
			...paramData,
			id: user_id,
			id_type: 'user_id'
		})
		if (!status) {
			//. check apikey
			status = await this.checkPermissionObject({
				...paramData,
				id: apikey,
				id_type: 'apikey'
			})
		}
		// return true;
		return status;
		
	}
	
	getHost(headers) {
		const origin =  headers['origin']
		
		let host = headers['x-forwarded-for'];
		if (origin) {
			host = url.parse(origin).hostname;
		}
		return host
	}
	
	async checkPermissionObject({id, id_type, host, collection, plugin, type, organization_id, document_id}) {
		if (!id) return false;
		
		const permission = await this.getRolesByKey(id, organization_id, id_type || "apikey")
		
		// console.log('---- permission sections ----')
		// console.log({document_id, permission})
		// console.log(this.checkDocument(permission['documents'], document_id, type))
		
		if (!permission) return false;
		
		if (!organization_id ) {
			return false;
		}
		
		if (permission.super_admin) return true;
		
		if (permission.organization_id !== organization_id) {
			return false;
		}
		
		if (!permission.hosts || !this.checkValue(permission.hosts, host)) {
			return false;
		}

		let status = this.checkCollection(permission['collections'], collection, type)
		if (!status) {
			status = this.checkDocument(permission['documents'], document_id, type)
		}
		if (!status) {
			status = this.checkPlugin(permission['plugins'], plugin, type)
		}

		
		return status;
	}
	
	checkCollection(collections, collection, action) 
	{
		if (!collections || !collection) return false;
		
		let collection_roles = collections[collection];
		if (collection_roles && collection_roles.length > 0) {
			let status = collection_roles.some(x => {
				if (CRUD_PERMISSION[x]) {
					return CRUD_PERMISSION[x].includes(action)
				} else {
					return x == action;
				}
			})
			return status;
		} else {
			return false;
		}
	}
	
	checkDocument(documents, document_id, action)
	{
		if (!documents || !document_id) return false
		let status = documents.some(x => x == document_id)

		return status;
	}
	
	checkPlugin(plugins, plugin, action) {
		console.log(plugins)
		if (!plugins || !plugin) return false;
		
		let selected_plugin = plugins[plugin]
		if (selected_plugin && selected_plugin.length >0) {
			let status = selected_plugin.some(x => x == action)
			return status;
		}
		return false;
	}
	
	checkValue(items, value) {
		if (!items) return false;
		if (items.includes("*") || items.includes(value)) {
			return true;
		}
		return false;
	}
}
module.exports = CoCreatePermission

