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
			let permission = await this.getPermissionObject(key, organization_id, type);
			this.permissions.set(key, permission)
			return permission
		}
	}
	
	//. overrride function
	getParameters(action, data) {
		return {};		
	}
	
	//. overrride function
	async getPermissionObject(key, organization_id, type) {
		return null;
	}
	
	async check(action, data, req, user_id) {
		const host = this.getHost(req.headers)
		const { apikey, ...paramData} = this.getParameters(action, data)
		paramData.host = host;

		console.log('paramData', paramData)
		let status = false
		status = await this.checkPermissionObject({
			...paramData,
			id: user_id,
			id_type: 'user_id'
		})
		if (!status) {
			status = await this.checkPermissionObject({
				...paramData,
				id: apikey,
				id_type: 'apikey'
			})
		}
		return status;
	}
	
	getHost(headers) {
		const origin =  headers['origin']
		let host = headers['x-forwarded-for'];
		if (origin && origin !== 'null') {
			host = url.parse(origin).hostname;
		}
		return host
	}
	
	async checkPermissionObject({id, id_type, host, collection, plugin, type, organization_id, document_id, name}) {
		if (!id) return false;
		
		const permission = await this.getRolesByKey(id, organization_id, id_type || "apikey")
				
		if (!permission) return false;
		
		if (!organization_id ) {
			return false;
		}

		if (permission.super_admin == 'true') {
			return true;
		}
		
		if (permission.organization_id !== organization_id) {
			return false;
		}
		
		if (!permission.hosts || !this.checkValue(permission.hosts, host)) {
			return false;
		}

		let status = this.checkCollection(permission['collections'], collection, type)
		if (status) {
			status = this.checkDocument(permission['documents'], document_id, type, name)
		}
		if (!status) {
			status = this.checkPlugin(permission['plugins'], plugin, type)
		}

		return status;
	}
	
	checkCollection(collections, collection, action) {
		if (!collections || !collection) return false;
		if (collections['*'] !== undefined)
			return true;
		let collection_roles = collections[collection];
		if (collection_roles && collection_roles.length > 0) {
			let status = collection_roles.some(x => {
				if (CRUD_PERMISSION[x]) {
					return CRUD_PERMISSION[x].includes(action) || CRUD_PERMISSION[x].includes('*');
				} else {
					return x == action;
				}
			})
			return status;
		} else {
			return false;
		}
	}
	
	checkDocument(documents, id, action, name) {
		let status = true;
		if (!documents || !id || !name) return true
		
		if (documents && id && documents[id]) {
			const { permissions, fields } = documents[id]
			const action_type = this.__getActionType(action)
			
			if (name && fields[name]) {
				status = fields[name].includes(action_type)
			} else {
				status = permissions.includes(action_type)
			} 
		} 

		return status;
	}
	
	checkPlugin(plugins, plugin, action) {
		if (!plugins || !plugin) return false;
		if (plugins['*'] !== undefined)
			return true;
		let selected_plugin = plugins[plugin]
		if (selected_plugin && selected_plugin.length > 0) {
			let status = selected_plugin.some(x => x == action || x == '*')
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
	
	__getActionType(action) {
		let action_type = action
		for (let key in CRUD_PERMISSION) {
			if (CRUD_PERMISSION[key].includes(action)) {
				action_type = key
				break;
			}
		}
		return action_type
	}
}
module.exports = CoCreatePermission

